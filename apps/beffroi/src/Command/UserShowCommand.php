<?php

declare(strict_types=1);

namespace App\Command;

use function array_filter;
use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Application\Credential\AuthenticatorModels;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\ModelDeclaringCredentialInterface;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use function implode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'beffroi:user:show',
    description: 'Show a user: the identity with the source that created it, the standard claims that are set, the credentials with their kind, identifier, name, authenticator, what their enrolment proved of it and dates, and the groups with the source of each membership.',
)]
final readonly class UserShowCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private CredentialRepositoryInterface $credentials,
        private GroupsOfAPersonInterface $groups,
        private AuthenticatorModels $models,
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

        $io->definitionList(...self::identity($user), ...self::claims($user));

        $io->section('Credentials');
        $credentials = $this->credentials->findByUser($user);
        if ($credentials === []) {
            $io->text('The user has no credential.');
        } else {
            $io->table(
                ['Kind', 'Id', 'Name', 'Authenticator', 'Created', 'Last used', 'Revoked'],
                array_map(fn (Credential $credential): array => [
                    $credential->kind(),
                    $credential->id->toRfc4122(),
                    PrintedText::of($credential->label() ?? ''),
                    $credential instanceof ModelDeclaringCredentialInterface ? PrintedText::of($this->authenticator($credential)) : '',
                    self::date($credential->createdAt),
                    self::date($credential->lastUsedAt),
                    $credential instanceof RevocableCredentialInterface ? self::date($credential->revokedAt) : '',
                ], $credentials),
            );
        }

        $io->section('Groups');
        $memberships = $this->groups->of($user);
        if ($memberships === []) {
            $io->text('The user is in no group.');
        } else {
            $io->table(
                ['Group', 'Source', 'Added'],
                array_map(static fn (GroupMembership $membership): array => [
                    PrintedText::of($membership->group->name),
                    $membership->source->value,
                    self::date($membership->addedAt),
                ], $memberships),
            );
        }

        return Command::SUCCESS;
    }

    private function authenticator(ModelDeclaringCredentialInterface $credential): string
    {
        $model = $this->models->of($credential);
        $proven = [$credential->modelProof->value];
        if ($credential->serialNumber !== null) {
            $proven[] = sprintf('serial number %s', $credential->serialNumber);
        }
        if ($credential->underSecurityAlert) {
            $proven[] = 'under a security alert';
        }

        return $model === null
            ? sprintf('unknown (AAGUID %s, %s)', $credential->aaguid->toRfc4122(), implode(', ', $proven))
            : sprintf('%s (%s, %s)', $model->name, $model->source, implode(', ', $proven));
    }

    /**
     * @return list<array<string, string>>
     */
    private static function identity(User $user): array
    {
        return [
            [
                'Username' => PrintedText::of($user->username),
            ],
            [
                'Subject' => PrintedText::of($user->subject->value),
            ],
            [
                'Status' => $user->isEnabled() ? 'enabled' : sprintf('disabled since %s', self::date($user->disabledAt)),
            ],
            [
                'Created' => self::date($user->createdAt),
            ],
            [
                'Email' => $user->email === null
                    ? ''
                    : sprintf('%s (%s)', PrintedText::of((string) $user->email), $user->emailVerified ? 'verified' : 'unverified'),
            ],
            [
                'Source' => PrintedText::of(self::source($user->source)),
            ],
        ];
    }

    private static function source(UserSource $source): string
    {
        $provider = $source->provider;
        if ($provider === null) {
            return 'local';
        }
        if ($source->claims === []) {
            return $provider;
        }

        return sprintf('%s, holding %s', $provider, implode(', ', $source->claims));
    }

    /**
     * OIDC Core §5.1
     *
     * @return list<array<string, string>>
     */
    public static function claims(User $user): array
    {
        return [
            [
                'Name' => PrintedText::of($user->profile->name ?? ''),
            ],
            [
                'Given name' => PrintedText::of($user->profile->givenName ?? ''),
            ],
            [
                'Family name' => PrintedText::of($user->profile->familyName ?? ''),
            ],
            [
                'Phone number' => $user->phoneNumber === null
                    ? ''
                    : sprintf('%s (%s)', PrintedText::of($user->phoneNumber), $user->phoneNumberVerified ? 'verified' : 'unverified'),
            ],
            [
                'Address' => $user->address === null
                    ? ''
                    : PrintedText::of(implode(', ', array_filter(
                        [
                            $user->address->streetAddress,
                            $user->address->postalCode,
                            $user->address->locality,
                            $user->address->region,
                            $user->address->country,
                        ],
                        static fn (?string $member): bool => $member !== null,
                    ))),
            ],
        ];
    }

    private static function date(?DateTimeImmutable $date): string
    {
        return $date?->format('Y-m-d H:i:s') ?? '';
    }
}
