<?php

declare(strict_types=1);

namespace App\Command;

use App\Doctrine\EntityManagers;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Precis\UsernameCaseMapped;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\UsernameRefusedException;
use Closure;
use function count;
use Doctrine\ORM\EntityManagerInterface;
use SortDirection;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Uid\Uuid;

/**
 * Two walks: the first names the usernames RFC 8265 §3.3 refuses and the persons whose usernames one tag would join,
 * the second schedules every person but those for an update, so that BlindIndexListener derives their tags again on
 * the flush. A refused username is indexed as written, the tag it had; persons joined keep theirs until renamed.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Derive again the blind indexes of every person of the tenant, after the projection of one changed, and name the usernames to rename.',
)]
final readonly class UserReindexCommand
{
    public const string NAME = 'beffroi:user:reindex';

    public const int PAGE = 100;

    public function __construct(
        private ConfiguredTenant $tenant,
        private EntityManagers $managers,
        private TenantBlindIndexes $indexes,
    ) {
    }

    public function __invoke(SymfonyStyle $io): int
    {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        $manager = $this->managers->forClass(User::class);
        $index = $this->indexes->of(BlindIndexedColumns::of(User::class, 'username'));
        $refused = [];
        $first = [];
        $joined = [];
        self::walk($manager, $tenant, static function (User $user) use ($index, &$refused, &$first, &$joined): void {
            try {
                UsernameCaseMapped::enforce($user->username);
            } catch (UsernameRefusedException) {
                $refused[] = [$user->id->toRfc4122(), PrintedText::of($user->username)];
            }
            // A tag and an identifier per person, never their usernames: a large tenant must fit in the memory of a console.
            $tag = $index->of($user->username);
            $id = $user->id->toBinary();
            if (isset($first[$tag])) {
                $joined[$tag] ??= [$first[$tag]];
                $joined[$tag][] = $id;
            } else {
                $first[$tag] = $id;
            }
        });
        $left = [];
        foreach ($joined as $ids) {
            foreach ($ids as $id) {
                $left[$id] = true;
            }
        }
        $derived = 0;
        self::walk($manager, $tenant, static function (User $user) use ($manager, $left, &$derived): void {
            if (! isset($left[$user->id->toBinary()])) {
                $manager->getUnitOfWork()->scheduleForUpdate($user);
                ++$derived;
            }
        });

        $io->success(sprintf('The blind indexes of %d person(s) of the tenant "%s" were derived again.', $derived, $tenant->slug));
        if ($refused !== []) {
            $io->warning(sprintf(
                'RFC 8265 §3.3 refuses the username of %d person(s), who sign in under it as written until an administrator renames them.',
                count($refused),
            ));
            $io->table(['Identifier', 'Username'], $refused);
        }
        foreach ($joined as $ids) {
            $io->warning(sprintf(
                '%d persons have usernames RFC 8265 §3.3.4 compares as one: their blind indexes were left as they were. Rename all of them but one, then run this command again.',
                count($ids),
            ));
            $io->table(['Identifier', 'Username'], self::rows($manager, $ids));
        }

        return $refused === [] && $joined === [] ? Command::SUCCESS : Command::FAILURE;
    }

    /**
     * @param list<string> $ids in bytes
     *
     * @return list<array{string, string}>
     */
    private static function rows(EntityManagerInterface $manager, array $ids): array
    {
        $rows = [];
        foreach ($ids as $id) {
            $user = $manager->find(User::class, Uuid::fromBinary($id));
            $rows[] = [Uuid::fromBinary($id)->toRfc4122(), PrintedText::of($user->username ?? '')];
        }

        return $rows;
    }

    /**
     * Page by page, each page flushed then cleared: the tenant is named by its identifier, every clear detaching its
     * entity.
     *
     * @param Closure(User): void $visit
     */
    private static function walk(EntityManagerInterface $manager, Tenant $tenant, Closure $visit): void
    {
        $walked = 0;
        do {
            /** @var list<User> $page */
            $page = $manager
                ->createQueryBuilder()
                ->select('u')
                ->from(User::class, 'u')
                ->where('u.tenant = :tenant')
                ->orderBy('u.id', SortDirection::Ascending)
                ->setParameter('tenant', $tenant->id, UuidType::NAME)
                ->setFirstResult($walked)
                ->setMaxResults(self::PAGE)
                ->getQuery()
                ->getResult();
            foreach ($page as $user) {
                $visit($user);
            }
            $manager->flush();
            $manager->clear();
            $walked += count($page);
        } while (count($page) === self::PAGE);
    }
}
