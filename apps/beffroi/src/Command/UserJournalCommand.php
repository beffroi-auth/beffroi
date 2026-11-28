<?php

declare(strict_types=1);

namespace App\Command;

use function array_map;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use function count;
use function implode;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use function json_encode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'List the acts of a user over a period, with the application each one was done on behalf of and the administrator who did one to them; for answering a request about what happened in their name.',
)]
final readonly class UserJournalCommand
{
    public const string NAME = 'beffroi:user:journal';

    public const string TABLE = 'table';

    public const string JSON = 'json';

    public const int READ_AT_ONCE = 200;

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private CanPageActsOfAPersonInterface $acts,
        private JournalRetention $retention,
    ) {
    }

    /**
     * @param list<string> $act
     */
    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user, or their identifier.')]
        string $username,
        #[Option(description: 'The first day to read, as YYYY-MM-DD on UTC, that day included; the whole of what the journal holds when not given.')]
        ?string $from = null,
        #[Option(description: 'The last day to read, as YYYY-MM-DD on UTC, that day included.')]
        ?string $to = null,
        #[Option(description: 'The name of an act to read, as the journal writes it ("tokens.issued"), repeatable; every act when not given.')]
        array $act = [],
        #[Option(description: 'The application the acts were done on behalf of, by the identifier it was registered under; every application when not given.')]
        ?string $client = null,
        #[Option(description: 'How the acts are written: a table to read, or JSON for a document a request is answered with.')]
        string $format = self::TABLE,
    ): int {
        if ($format !== self::TABLE && $format !== self::JSON) {
            $io->error(sprintf('The format "%s" is neither "%s" nor "%s".', $format, self::TABLE, self::JSON));

            return Command::FAILURE;
        }
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        try {
            $period = Period::ofDays(self::day($from, 'from'), self::day($to, 'to'));
        } catch (InvalidArgumentException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::FAILURE;
        }
        $acts = $this->everyActOf($user, new JournalQuestion($act, $client, $period));

        return $format === self::JSON
            ? $this->writeDocument($io, $user, $period, $acts)
            : $this->writeTable($io, $user, $period, $acts);
    }

    /**
     * @return list<JournalEntry>
     */
    private function everyActOf(User $user, JournalQuestion $question): array
    {
        $acts = [];
        $number = 1;
        do {
            $page = $this->acts->pageOfActs($user, $question, new Pagination($number, self::READ_AT_ONCE));
            foreach ($page as $entry) {
                $acts[] = $entry;
            }
            ++$number;
        } while ($page->hasNext());

        return $acts;
    }

    /**
     * @param list<JournalEntry> $acts
     */
    private function writeTable(SymfonyStyle $io, User $user, ?Period $period, array $acts): int
    {
        $io->title(sprintf('Journal of "%s"', PrintedText::of($user->username)));
        if ($acts === []) {
            $io->text(sprintf('The journal holds no act of "%s" over that stretch of time.', PrintedText::of($user->username)));
        } else {
            $io->table(
                ['Act', 'Occurred (UTC)', 'Application', 'From', 'Author'],
                array_map(static fn (JournalEntry $entry): array => [
                    $entry->act,
                    $entry->occurredAt->format('Y-m-d H:i:s'),
                    PrintedText::of($entry->client ?? ''),
                    $entry->context->ipAddress ?? 'address not recorded',
                    PrintedText::of($entry->author === null ? '' : implode(' ', $entry->author->toDocument())),
                ], $acts),
            );
            $io->text(sprintf('%d act(s), most recent first.', count($acts)));
        }
        $io->text($this->whereTheJournalStops($period));

        return Command::SUCCESS;
    }

    /**
     * @param list<JournalEntry> $acts
     */
    private function writeDocument(SymfonyStyle $io, User $user, ?Period $period, array $acts): int
    {
        $io->writeln(json_encode(
            [
                'username' => $user->username,
                'sub' => $user->subject->value,
                'period' => [
                    'from' => ArchivedFacts::moment($period?->from),
                    'to' => ArchivedFacts::moment($period?->to),
                ],
                'kept' => [
                    'days' => $this->retention->window->days,
                    'since' => ArchivedFacts::moment($this->retention->keptSince()),
                ],
                'acts' => array_map(ArchivedFacts::actAsWritten(...), $acts),
            ],
            JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
        ), OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }

    private function whereTheJournalStops(?Period $period): string
    {
        $since = $this->retention->keptSince();
        $covered = $period?->from !== null && $period->from >= $since;

        return $covered
            ? sprintf('This deployment keeps an act %d day(s); the whole of that period is inside it.', $this->retention->window->days)
            : sprintf(
                'This deployment keeps an act %d day(s): nothing that happened before %s is held, whatever this reading asked for.',
                $this->retention->window->days,
                $since->format('Y-m-d H:i:s'),
            );
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function day(?string $asked, string $option): ?DateTimeImmutable
    {
        if ($asked === null || $asked === '') {
            return null;
        }
        $day = DateTimeImmutable::createFromFormat('!Y-m-d', $asked, new DateTimeZone('UTC'));
        if ($day === false) {
            throw new InvalidArgumentException(sprintf('The option "--%s" takes a day as YYYY-MM-DD, "%s" given.', $option, $asked));
        }

        return $day;
    }
}
