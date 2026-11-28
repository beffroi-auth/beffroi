<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Domain\Author\TheHost;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Uid\Uuid;
use function trim;

#[AsCommand(
    name: self::NAME,
    description: 'Revoke a credential of a user by its identifier; the credential stays listed as revoked.',
)]
final readonly class UserRevokeCredentialCommand
{
    public const string NAME = 'beffroi:user:revoke-credential';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private CredentialRepositoryInterface $credentials,
        private CredentialRevocation $revocation,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user, or their identifier.')]
        string $username,
        #[Argument(description: 'The identifier of the credential, as "beffroi:user:show" lists it.')]
        string $id,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if (! Uuid::isValid(trim($id))) {
            $io->error(sprintf('"%s" is not the identifier of a credential.', trim($id)));

            return Command::INVALID;
        }

        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        $credential = $this->credentials->find(Uuid::fromString(trim($id)));
        if ($credential === null || ! $credential->user->id->equals($user->id)) {
            $io->error(sprintf('The user "%s" has no credential "%s".', PrintedText::inBlock($user->username), trim($id)));

            return Command::FAILURE;
        }
        $kind = $credential->kind();
        if (! $credential instanceof RevocableCredentialInterface) {
            $io->error(sprintf('The %s "%s" cannot be revoked; a %s is replaced, not revoked.', $kind, trim($id), $kind));

            return Command::INVALID;
        }
        $label = $credential->label() ?? trim($id);
        if ($credential->isRevoked()) {
            $io->warning(sprintf(
                'The %s "%s" was revoked on %s already.',
                $kind,
                PrintedText::inBlock($label),
                $credential->revokedAt?->format('Y-m-d H:i:s'),
            ));

            return Command::SUCCESS;
        }

        $this->revocation->revoke($credential, new TheHost(), $this->contexts->fromConsole(self::NAME));
        $io->success(sprintf(
            'The %s "%s" of the user "%s" is revoked; it never authenticates again.',
            $kind,
            PrintedText::inBlock($label),
            PrintedText::inBlock($user->username),
        ));

        return Command::SUCCESS;
    }
}
