<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Application\Identity\IdentityAlreadyLinkedException;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'beffroi:user:link',
    description: 'Say that a user of the tenant is a given subject at an upstream provider; run again to refresh it.',
)]
final readonly class UserLinkCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private IdentityLinker $linker,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user of this tenant, or their identifier.')]
        string $username,
        #[Argument(description: 'The upstream provider, as the registration that trusts it names it (the "identity_provider" of a trusted issuer).')]
        string $provider,
        #[Argument(description: 'The subject that provider gives for this user, compared byte for byte.')]
        string $subject,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }

        try {
            $identity = $this->linker->link($user, $provider, $subject);
        } catch (InvalidArgumentException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::INVALID;
        } catch (IdentityAlreadyLinkedException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::FAILURE;
        }

        $io->definitionList(
            [
                'Username' => PrintedText::of($user->username),
            ],
            [
                'Provider' => $identity->provider,
            ],
            [
                'Subject' => $identity->subject,
            ],
            [
                'Identifier' => $identity->id->toRfc4122(),
            ],
            [
                'Tenant' => $tenant->slug,
            ],
        );
        $io->success(sprintf(
            'The subject "%s" of the provider "%s" is the user "%s".',
            $identity->subject,
            $identity->provider,
            PrintedText::inBlock($user->username),
        ));

        return Command::SUCCESS;
    }
}
