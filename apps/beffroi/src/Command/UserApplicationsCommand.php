<?php

declare(strict_types=1);

namespace App\Command;

use function array_map;
use App\Account\ApplicationHolding;
use App\Account\ApplicationHoldings;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use function count;
use DateTimeImmutable;
use function implode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'List the applications a user agreed to, with what each one holds of them and what it has asked that is still waiting.',
)]
final readonly class UserApplicationsCommand
{
    public const string NAME = 'beffroi:user:applications';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private ActiveConsentsInterface $consents,
        private ApplicationHoldings $holdings,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user, or their identifier.')]
        string $username,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        $consents = $this->consents->activeOf($user);
        if ($consents === []) {
            $io->text(sprintf('"%s" has agreed to let no application obtain anything about them.', PrintedText::of($user->username)));

            return Command::SUCCESS;
        }
        $io->title(sprintf('Applications of "%s"', PrintedText::of($user->username)));
        $io->table(
            ['Client id', 'Name', 'Access', 'Granted', 'Renewable', 'Last renewed', 'Awaiting'],
            array_map(
                static fn (ApplicationHolding $holding): array => [
                    $holding->consent->clientId,
                    PrintedText::of($holding->consent->client->registration->presentation->name),
                    self::access($holding->consent),
                    self::date($holding->consent->grantedAt),
                    (string) $holding->renewable,
                    self::date($holding->lastIssued),
                    (string) count($holding->pending),
                ],
                $this->holdings->ofEach($user, $consents),
            ),
        );
        $io->text('An access token already issued lives to its own expiry, which taking a consent back does not shorten.');

        return Command::SUCCESS;
    }

    private static function access(Consent $consent): string
    {
        $scopes = (string) $consent->scopes;

        return $consent->claims->isEmpty() ? $scopes : sprintf('%s, by name: %s', $scopes, implode(' ', $consent->claims->all));
    }

    private static function date(?DateTimeImmutable $date): string
    {
        return $date?->format('Y-m-d H:i') ?? '';
    }
}
