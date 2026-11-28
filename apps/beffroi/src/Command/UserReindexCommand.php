<?php

declare(strict_types=1);

namespace App\Command;

use App\Doctrine\EntityManagers;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Precis\UsernameCaseMapped;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\UsernameRefusedException;
use function bin2hex;
use Closure;
use function count;
use Doctrine\ORM\EntityManagerInterface;
use function random_bytes;
use SortDirection;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Uid\Uuid;

/**
 * Two walks: the first names the usernames RFC 8265 §3.3 refuses and the persons whose usernames one tag would join,
 * the second writes the tags of each person under the projections of this build, and a tag drawn at random for each
 * person joined, whom no lookup finds until renamed rather than one found under the name of the other. The derivation
 * is recorded at the end (BlindIndexDerivations).
 */
#[AsCommand(
    name: self::NAME,
    description: 'Derive the blind indexes of every person of the tenant under the projections of this build, and name the usernames to rename.',
)]
final readonly class UserReindexCommand
{
    public const string NAME = 'beffroi:user:reindex';

    public const int PAGE = 100;

    /**
     * Every tag is derived, and persons are named whom an administrator renames: no failure of the deployment.
     */
    public const int PERSONS_NAMED = 3;

    public function __construct(
        private ConfiguredTenant $tenant,
        private EntityManagers $managers,
        private TenantBlindIndexes $indexes,
        private BlindIndexDerivations $derivations,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(
            description: 'Walk the tenant only when its tags were not derived under the projections and the version of Unicode of this build, as the image does at every start.',
        )]
        bool $whenDue = false,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if ($whenDue && $this->derivations->isCurrent($tenant)) {
            $io->success(sprintf('The blind indexes of the tenant "%s" are derived under the projections of this build.', $tenant->slug));

            return Command::SUCCESS;
        }

        $manager = $this->managers->forClass(User::class);
        $usernames = $this->indexes->of(BlindIndexedColumns::of(User::class, 'username'));
        $refused = [];
        $first = [];
        $joined = [];
        self::walk($manager, $tenant, static function (User $user) use ($usernames, &$refused, &$first, &$joined): void {
            try {
                UsernameCaseMapped::enforce($user->username);
            } catch (UsernameRefusedException) {
                $refused[] = [$user->id->toRfc4122(), PrintedText::of($user->username)];
            }
            // A tag and an identifier per person, never their usernames: a large tenant must fit in the memory of a console.
            $tag = $usernames->of($user->username);
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
        self::walk($manager, $tenant, function (User $user) use ($manager, $usernames, $left, &$derived): void {
            $set = isset($left[$user->id->toBinary()]);
            $this->write($manager, $user, $set ? bin2hex(random_bytes(32)) : $usernames->of($user->username));
            $derived += $set ? 0 : 1;
        });
        $this->derivations->record($tenant, count($refused), count($left));

        $io->success(sprintf('The blind indexes of %d person(s) of the tenant "%s" were derived again.', $derived, $tenant->slug));
        if ($refused !== []) {
            $io->warning(sprintf(
                'RFC 8265 §3.3 refuses the username of %d person(s), who sign in under it as written until an administrator renames them, and at the latest until 1.0.0.',
                count($refused),
            ));
            $io->table(['Identifier', 'Username'], $refused);
        }
        foreach ($joined as $ids) {
            $io->warning(sprintf(
                '%d persons have usernames RFC 8265 §3.3.4 compares as one, and no lookup finds them until they are renamed. Rename all of them but one with "beffroi:user:rename <identifier> <username>", then run this command again.',
                count($ids),
            ));
            [$rows, $before] = self::holders($manager, $ids);
            $io->table(['Identifier', 'Username'], $rows);
            $io->text(
                $before === null
                    ? 'Before, any other spelling of their username named nobody.'
                    : sprintf('Before, each username named the person written so, and any other spelling named %s.', $before),
            );
        }

        return $refused === [] && $joined === [] ? Command::SUCCESS : self::PERSONS_NAMED;
    }

    /**
     * Through DBAL, not the unit of work: the listener derives a tag when its value changes, and these values do not.
     */
    private function write(EntityManagerInterface $manager, User $user, string $usernameTag): void
    {
        $emailTag = $user->email === null ? null : $this->indexes->of(BlindIndexedColumns::of(User::class, 'email'))->of($user->email->value);
        if ($usernameTag === $user->usernameIndex && $emailTag === $user->emailIndex) {
            return;
        }
        $metadata = $manager->getClassMetadata(User::class);
        $manager->getConnection()->update(
            $metadata->getTableName(),
            [
                $metadata->getColumnName('usernameIndex') => $usernameTag,
                $metadata->getColumnName('emailIndex') => $emailTag,
            ],
            [
                $metadata->getColumnName('id') => $user->id,
            ],
            [
                $metadata->getColumnName('id') => UuidType::NAME,
            ],
        );
    }

    /**
     * @param list<string> $ids in bytes
     *
     * @return array{list<array{string, string}>, ?string} the rows, and the one whose username is the enforced form
     */
    private static function holders(EntityManagerInterface $manager, array $ids): array
    {
        $rows = [];
        $before = null;
        foreach ($ids as $id) {
            $identifier = Uuid::fromBinary($id)->toRfc4122();
            $username = $manager->find(User::class, Uuid::fromBinary($id))->username ?? '';
            $rows[] = [$identifier, PrintedText::of($username)];
            if (UsernameCaseMapped::comparisonForm($username) === $username) {
                $before = $identifier;
            }
        }

        return [$rows, $before];
    }

    /**
     * Page by page, each page cleared: the tenant is named by its identifier, every clear detaching its entity.
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
            $manager->clear();
            $walked += count($page);
        } while (count($page) === self::PAGE);
    }
}
