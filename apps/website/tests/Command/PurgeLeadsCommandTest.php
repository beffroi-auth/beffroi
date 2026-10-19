<?php

declare(strict_types=1);

namespace App\Tests\Command;

use DateTimeImmutable;
use LogicException;
use App\Entity\Lead;
use App\Lead\OidcProvider;
use App\Tests\DatabaseReset;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\Console\Tester\CommandTester;

final class PurgeLeadsCommandTest extends KernelTestCase
{
    use ClockSensitiveTrait;
    use DatabaseReset;

    protected function setUp(): void
    {
        self::bootKernel();
        self::resetDatabase();
        self::mockTime('2027-11-27 12:00:00');
    }

    #[Test]
    public function itDeletesALeadWhoseConsentIsTwelveMonthsOld(): void
    {
        // Given
        $this->givenALeadConsentedAt('ada@example.com', '2026-11-26 12:00:00');

        // When
        $this->purge();

        // Then
        static::assertSame(0, self::entityManager()->getRepository(Lead::class)->count());
    }

    #[Test]
    public function itKeepsALeadWhoseConsentIsRecent(): void
    {
        // Given
        $this->givenALeadConsentedAt('ada@example.com', '2026-11-28 12:00:00');

        // When
        $this->purge();

        // Then
        static::assertSame(1, self::entityManager()->getRepository(Lead::class)->count());
    }

    private function givenALeadConsentedAt(string $email, string $date): void
    {
        self::entityManager()->persist(new Lead($email, 'Ada', 'Lovelace', null, OidcProvider::None, null, 'test', new DateTimeImmutable($date)));
        self::entityManager()->flush();
        self::entityManager()->clear();
    }

    private function purge(): void
    {
        $kernel = self::$kernel ?? throw new LogicException('The kernel is booted in setUp().');
        $tester = new CommandTester(new Application($kernel)->find('app:leads:purge'));
        $tester->execute([]);
        $tester->assertCommandIsSuccessful();
    }
}
