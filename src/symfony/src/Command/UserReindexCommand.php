<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Identity\User;
use function count;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Derives again the blind indexes of every person of the tenant, under the projections the bundle declares
 * now (`BlindIndexedColumns`, decision 0011): what a deployment runs once after a projection changed, the
 * address folded whole since issue #781 where only its domain was before.
 *
 * A tag written under the old projection is a row no search finds, and a row repairs itself only when it is
 * written again (`BlindIndexListener`), which a person who changes nothing never is. So each person is
 * scheduled for an update, the listener derives its tags on the flush as it does on any write, and only a
 * tag that differs is written: a row whose address had no capital letter in its local part keeps the tag it
 * had, both projections giving the same string. A second run writes nothing.
 *
 * In pages, the manager cleared after each one, so a tenant of any size holds one page in memory; the
 * values are opened from their sealed columns as any read opens them, under the data key of the tenant.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Derive again the blind indexes of every person of the tenant, after the projection of one changed.',
)]
final readonly class UserReindexCommand
{
    public const string NAME = 'beffroi:user:reindex';

    /**
     * How many persons one flush writes, and the manager holds at once.
     */
    public const int PAGE = 100;

    public function __construct(
        private ConfiguredTenant $tenant,
        private EntityManagers $managers,
    ) {
    }

    public function __invoke(SymfonyStyle $io): int
    {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        $manager = $this->managers->forClass(User::class);
        $walked = 0;
        do {
            // the tenant is named by its identifier, the row the provider holds being forgotten with the rest
            // at every clear
            /** @var list<User> $page */
            $page = $manager
                ->createQueryBuilder()
                ->select('u')
                ->from(User::class, 'u')
                ->where('u.tenant = :tenant')
                ->orderBy('u.id', 'ASC')
                ->setParameter('tenant', $tenant->id, UuidType::NAME)
                ->setFirstResult($walked)
                ->setMaxResults(self::PAGE)
                ->getQuery()
                ->getResult();
            foreach ($page as $user) {
                $manager->getUnitOfWork()->scheduleForUpdate($user);
            }
            $manager->flush();
            $manager->clear();
            $walked += count($page);
        } while (count($page) === self::PAGE);

        $io->success(sprintf('The blind indexes of %d person(s) of the tenant "%s" were derived again.', $walked, $tenant->slug));

        return Command::SUCCESS;
    }
}
