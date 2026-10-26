<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use function array_map;
use function count;
use DateTimeImmutable;
use DateTimeInterface;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\RotationSchedulesInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Psr\Clock\ClockInterface;
use function implode;
use function in_array;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

/**
 * The keys of the tenant with what they are published for, their state and every date of their life
 * (architecture §3.3): the ones the JWK Set publishes, and the retired ones on request. On request too,
 * whether the KMS still opens the keys in use or about to be: a KMS that lost its master key leaves
 * envelopes nothing can open, which the first signature, or the first JWE, would be the one to find out.
 *
 * A key it cannot open is named with its algorithm, and so is the run that reaches it: a rotation reaches
 * one algorithm, and a tenant publishes one key per algorithm it serves, so a KMS that forgot its master
 * key leaves as many dead keys as the tenant has algorithms and as many rotations to do.
 *
 * **It also says when a key has worked past its age with nothing staged behind it** (issue #455), which is
 * what a planning that has stopped looks like from outside: the step that stages a successor runs every
 * minute, so an active key past its age and no staged key of its algorithm is a worker that is not
 * consuming, and nothing else. The age is the one of the family of the key (issue #738).
 */
#[AsCommand(
    name: 'beffroi:keys:list',
    description: 'List the keys of the tenant with their use, status and dates: the published ones, or every key with --all; --check opens the keys in use, or about to be, with the KMS and fails on one it cannot open or that has worked past its age with nothing staged behind it.',
)]
final readonly class KeysListCommand
{
    /**
     * @param RotationSchedulesInterface $schedules how long a key of each family works before the planning stages a successor
     */
    public function __construct(
        private ConfiguredTenant $tenant,
        private TenantKeyRepositoryInterface $keys,
        private KeySealerInterface $sealer,
        private RotationSchedulesInterface $schedules,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'Include the retired keys, out of the JWK Set for good.')]
        bool $all = false,
        #[Option(
            description: 'Open the active and the staged keys with the KMS and say whether each one opens; a retiring key is opened only to read what was encrypted to it. Says of an active key whether it has worked past its age and whether a successor is staged behind it. Fails when a key does not open, or has worked past its age with nothing staged.',
        )]
        bool $check = false,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        $keys = $all ? $this->keys->findAll($tenant) : $this->keys->findInService($tenant);
        if ($keys === []) {
            $io->warning(sprintf('The tenant "%s" has no %skey: nothing can be signed. Run "beffroi:keys:rotate".', $tenant->slug, $all ? '' : 'published '));

            return Command::SUCCESS;
        }

        /** @var list<TenantKey> $dead */
        $dead = [];
        /** @var list<TenantKey> $overdue */
        $overdue = [];
        $now = $this->clock->now();
        // read over every key given, so that a successor staged behind an old one is seen whichever list
        // was asked for
        $awaited = self::algorithmsAwaiting($keys);
        foreach ($keys as $key) {
            $rows = self::describe($key);
            if ($check && ($key->status === KeyStatus::Staged || $key->status === KeyStatus::Active)) {
                $failure = $this->failureToOpen($tenant, $key);
                $rows[] = [
                    'Opens with the KMS' => $failure === null ? 'yes' : 'no: ' . $failure,
                ];
                if ($failure !== null) {
                    $dead[] = $key;
                }
            }
            if ($check && $key->status === KeyStatus::Active) {
                $reached = $key->hasReachedItsAge($now, $this->schedules->of($key->algorithm)->age);
                $staged = in_array($key->algorithm->name(), $awaited, true);
                $rows[] = [
                    'Has worked past its age' => match (true) {
                        ! $reached => 'no',
                        $staged => 'yes, and a successor is staged',
                        default => 'yes, and nothing is staged',
                    },
                ];
                if ($reached && ! $staged) {
                    $overdue[] = $key;
                }
            }
            $io->definitionList(...$rows);
        }
        if ($overdue !== []) {
            $io->error([
                sprintf(
                    'The key%s %s of "%s" %s worked past the age of a key and nothing is staged behind %s.',
                    count($overdue) === 1 ? '' : 's',
                    implode(', ', array_map(
                        static fn (TenantKey $key): string => sprintf('%s (%s)', $key->kid, $key->algorithm->name()),
                        $overdue,
                    )),
                    $tenant->slug,
                    count($overdue) === 1 ? 'has' : 'have',
                    count($overdue) === 1 ? 'it' : 'them',
                ),
                'The planning stages a successor every minute, so this is a worker that is not consuming the schedule: start it, or consume the transport by hand ("messenger:consume scheduler_beffroi"). A rotation by hand does the same thing for one algorithm:'
                    . \PHP_EOL
                    . implode(\PHP_EOL, array_map(
                        static fn (string $algorithm): string => sprintf('  %s --algorithm=%s', KeysRotateCommand::NAME, $algorithm),
                        self::algorithmsOf($overdue),
                    )),
            ]);
        }
        if ($dead !== []) {
            $io->error([
                sprintf(
                    'The KMS cannot open the key%s %s of "%s": nothing is done with %s.',
                    count($dead) === 1 ? '' : 's',
                    implode(', ', array_map(
                        static fn (TenantKey $key): string => sprintf('%s (%s)', $key->kid, $key->algorithm->name()),
                        $dead,
                    )),
                    $tenant->slug,
                    count($dead) === 1 ? 'it' : 'them',
                ),
                'If the KMS is not reachable, start it and run this command again. If the KMS lost the master key (Vault in dev mode and LocalStack forget everything when they restart), the envelopes sealed under it are dead: a rotation publishes a key sealed under the master key the KMS has now and signs with it at once, the dead key retires with its window, its public half still verifying what it signed. Nothing is deleted.',
                // One entry and not one per run, so that the runs read as a list a block does not space out.
                'A rotation reaches one algorithm, the default one when none is named, so each algorithm above has its own run:'
                    . \PHP_EOL
                    . implode(\PHP_EOL, array_map(
                        static fn (string $algorithm): string => sprintf('  %s --now --algorithm=%s', KeysRotateCommand::NAME, $algorithm),
                        self::algorithmsOf($dead),
                    )),
            ]);

            return Command::FAILURE;
        }

        return $overdue === [] ? Command::SUCCESS : Command::FAILURE;
    }

    /**
     * The algorithms a staged key is waiting for, which is what tells an active key past its age from one
     * whose successor is already in the JWK Set.
     *
     * @param list<TenantKey> $keys
     *
     * @return list<string>
     */
    private static function algorithmsAwaiting(array $keys): array
    {
        $awaited = [];
        foreach ($keys as $key) {
            if ($key->status === KeyStatus::Staged && ! in_array($key->algorithm->name(), $awaited, true)) {
                $awaited[] = $key->algorithm->name();
            }
        }

        return $awaited;
    }

    /**
     * The algorithms of the keys the KMS cannot open, each once and in the order they were listed: one
     * rotation reaches one algorithm, so two dead keys of the same one are one run and not two.
     *
     * @param list<TenantKey> $dead
     *
     * @return list<string>
     */
    private static function algorithmsOf(array $dead): array
    {
        $algorithms = [];
        foreach ($dead as $key) {
            $algorithm = $key->algorithm->name();
            if (! in_array($algorithm, $algorithms, true)) {
                $algorithms[] = $algorithm;
            }
        }

        return $algorithms;
    }

    /**
     * Why the KMS does not open the key, or null when it does: the message of the sealer and of what it
     * wraps (the bridge names the KMS it failed to reach or the key it does not know), never the material.
     */
    private function failureToOpen(Tenant $tenant, TenantKey $key): ?string
    {
        try {
            $this->sealer->unseal($tenant, $key->sealedPrivateJwk);
        } catch (Throwable $exception) {
            return ExceptionTrail::of($exception);
        }

        return null;
    }

    /**
     * The dates a key has, by the transitions it went through; a staged key says when it activates.
     *
     * @return list<array<string, string>>
     */
    private static function describe(TenantKey $key): array
    {
        $rows = [
            [
                'Key identifier' => $key->kid,
            ],
            [
                'Algorithm' => $key->algorithm->name(),
            ],
            [
                'Use' => $key->algorithm->keyUse()->value,
            ],
            [
                'Status' => $key->status->value,
            ],
            [
                'Created at' => self::date($key->createdAt),
            ],
        ];
        if ($key->status === KeyStatus::Staged) {
            $rows[] = [
                'Activates at' => self::date($key->activationDueAt),
            ];

            return $rows;
        }
        $rows[] = [
            'Activated at' => self::date($key->activatedAt),
        ];
        if ($key->status === KeyStatus::Active) {
            return $rows;
        }
        $rows[] = [
            'Retiring since' => self::date($key->retiringAt),
        ];
        $rows[] = [
            'Retirement due at' => self::date($key->retirementDueAt),
        ];
        if ($key->status === KeyStatus::Retired) {
            $rows[] = [
                'Retired at' => self::date($key->retiredAt),
            ];
        }

        return $rows;
    }

    private static function date(?DateTimeImmutable $date): string
    {
        return $date?->format(DateTimeInterface::RFC3339) ?? '?';
    }
}
