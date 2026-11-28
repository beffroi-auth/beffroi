<?php

declare(strict_types=1);

namespace App\Command;

use function hash_equals;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Exception\PasswordRefusedException;
use function is_string;
use function preg_replace;
use function sprintf;
use const STDIN;
use function stream_get_contents;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\StreamableInputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'beffroi:user:set-password',
    description: 'Set or replace the password of a user, asked on the terminal or read from the standard input.',
)]
final readonly class UserSetPasswordCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private UserProvisioner $provisioner,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        InputInterface $input,
        #[Argument(description: 'The username of the user, or their identifier.')]
        string $username,
        #[Option(description: 'Read the password from the standard input, up to the end of the first line, instead of asking.')]
        bool $passwordStdin = false,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }

        $password = $passwordStdin ? self::fromStandardInput($input) : self::fromTerminal($io, $input);
        if ($password === null) {
            return Command::INVALID;
        }
        if ($password === '') {
            $io->error('The password is empty.');

            return Command::INVALID;
        }

        try {
            $this->provisioner->setPassword(
                $user,
                new PlainPassword($password, PasswordLength::under($user->tenant->loginFloor)),
            );
        } catch (PasswordRefusedException|CredentialEnrolmentFailedException $exception) {
            $io->error(PrintedText::inBlock($exception->getMessage()));

            return Command::INVALID;
        }

        $io->success(sprintf('The password of "%s" is set.', PrintedText::inBlock($user->username)));

        return Command::SUCCESS;
    }

    private static function fromStandardInput(InputInterface $input): string
    {
        $stream = $input instanceof StreamableInputInterface ? $input->getStream() : null;
        $contents = stream_get_contents($stream ?? STDIN);

        return $contents === false ? '' : preg_replace('/\r?\n.*$/Ds', '', $contents) ?? '';
    }

    private static function fromTerminal(SymfonyStyle $io, InputInterface $input): ?string
    {
        if (! $input->isInteractive()) {
            $io->error('No terminal to ask the password on: pass --password-stdin and write it on the standard input.');

            return null;
        }
        $password = $io->askHidden('Password');
        $again = $io->askHidden('Password (again)');
        $password = is_string($password) ? $password : '';
        $again = is_string($again) ? $again : '';
        if (! hash_equals($password, $again)) {
            $io->error('The two passwords differ.');

            return null;
        }

        return $password;
    }
}
