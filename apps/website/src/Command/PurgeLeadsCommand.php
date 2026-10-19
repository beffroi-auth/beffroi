<?php

declare(strict_types=1);

namespace App\Command;

use App\Repository\LeadRepository;
use Psr\Clock\ClockInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Deletes the leads whose last consent is twelve months old, the retention period the privacy notice states.
 * The scheduler of the platform runs it every day (cron.json).
 */
#[AsCommand(name: 'app:leads:purge', description: 'Deletes the leads kept for longer than the retention period')]
final readonly class PurgeLeadsCommand
{
    public const string RETENTION = '12 months';

    public function __construct(
        private LeadRepository $leads,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(SymfonyStyle $io): int
    {
        $limit = $this->clock->now()->modify('-' . self::RETENTION);
        $deleted = $this->leads->deleteConsentedBefore($limit);

        $io->success(\sprintf('%d lead(s) consented before %s and were deleted.', $deleted, $limit->format(\DATE_ATOM)));

        return Command::SUCCESS;
    }
}
