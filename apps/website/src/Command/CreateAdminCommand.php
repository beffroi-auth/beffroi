<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\Admin;
use App\Repository\AdminRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Creates an account of the back office, or sets a new password on an existing one. The password is asked, never
 * passed as an argument, so that it stays out of the shell history and the process list.
 */
#[AsCommand(name: 'app:admin:create', description: 'Creates an admin of the back office, or resets its password')]
final readonly class CreateAdminCommand
{
    private const int MIN_LENGTH = 12;

    public function __construct(
        private AdminRepository $admins,
        private EntityManagerInterface $entityManager,
        private UserPasswordHasherInterface $hasher,
    ) {
    }

    public function __invoke(SymfonyStyle $io, #[Argument('The email address the admin signs in with')] string $email): int
    {
        $email = mb_strtolower(trim($email));
        if (false === filter_var($email, \FILTER_VALIDATE_EMAIL)) {
            $io->error('The email address is not valid.');

            return Command::INVALID;
        }

        $password = $this->askHidden($io, 'Password (12 characters at least)');
        if (mb_strlen($password) < self::MIN_LENGTH) {
            $io->error(\sprintf('A password has %d characters at least.', self::MIN_LENGTH));

            return Command::INVALID;
        }
        if ($password !== $this->askHidden($io, 'The same password again')) {
            $io->error('The two passwords differ.');

            return Command::INVALID;
        }

        $admin = $this->admins->findOneByEmail($email);
        if (null === $admin) {
            $admin = new Admin($email, '');
            $admin->changePassword($this->hasher->hashPassword($admin, $password));
            $this->entityManager->persist($admin);
            $this->entityManager->flush();
            $io->success(\sprintf('%s can now sign in to the back office.', $email));

            return Command::SUCCESS;
        }

        $admin->changePassword($this->hasher->hashPassword($admin, $password));
        $this->entityManager->flush();
        $io->success(\sprintf('The password of %s has changed.', $email));

        return Command::SUCCESS;
    }

    /**
     * What was typed at a hidden question. Nothing typed is the empty password, which the length refuses.
     */
    private function askHidden(SymfonyStyle $io, string $question): string
    {
        $answer = $io->askHidden($question);

        return \is_string($answer) ? $answer : '';
    }
}
