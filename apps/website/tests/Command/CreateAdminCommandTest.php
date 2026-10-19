<?php

declare(strict_types=1);

namespace App\Tests\Command;

use LogicException;
use App\Entity\Admin;
use App\Tests\DatabaseReset;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class CreateAdminCommandTest extends KernelTestCase
{
    use DatabaseReset;

    protected function setUp(): void
    {
        self::bootKernel();
        self::resetDatabase();
    }

    #[Test]
    public function itCreatesAnAdminWithThePasswordTypedTwice(): void
    {
        // When
        $status = $this->createAdmin('Admin@Beffroi.tech', ['a long enough password', 'a long enough password']);

        // Then
        static::assertSame(Command::SUCCESS, $status);
        static::assertTrue($this->passwordIsValid('admin@beffroi.tech', 'a long enough password'));
    }

    #[Test]
    public function itSetsANewPasswordOnAnExistingAdmin(): void
    {
        // Given
        $this->createAdmin('admin@beffroi.tech', ['a long enough password', 'a long enough password']);

        // When
        $this->createAdmin('admin@beffroi.tech', ['another long password', 'another long password']);

        // Then
        static::assertTrue($this->passwordIsValid('admin@beffroi.tech', 'another long password'));
    }

    #[Test]
    public function itRefusesAPasswordShorterThanTwelveCharacters(): void
    {
        // When
        $status = $this->createAdmin('admin@beffroi.tech', ['too short', 'too short']);

        // Then
        static::assertSame(Command::INVALID, $status);
        static::assertSame(0, self::entityManager()->getRepository(Admin::class)->count());
    }

    #[Test]
    public function itRefusesTwoPasswordsThatDiffer(): void
    {
        // When
        $status = $this->createAdmin('admin@beffroi.tech', ['a long enough password', 'another long password']);

        // Then
        static::assertSame(Command::INVALID, $status);
        static::assertSame(0, self::entityManager()->getRepository(Admin::class)->count());
    }

    /**
     * @param list<string> $inputs
     */
    private function createAdmin(string $email, array $inputs): int
    {
        $kernel = self::$kernel ?? throw new LogicException('The kernel is booted in setUp().');
        $tester = new CommandTester(new Application($kernel)->find('app:admin:create'));
        $tester->setInputs($inputs);

        return $tester->execute(['email' => $email]);
    }

    private function passwordIsValid(string $email, string $password): bool
    {
        self::entityManager()->clear();
        $admin = self::entityManager()->getRepository(Admin::class)->findOneBy(['email' => $email]);
        static::assertInstanceOf(Admin::class, $admin);
        return static::getContainer()->get(UserPasswordHasherInterface::class)->isPasswordValid($admin, $password);
    }
}
