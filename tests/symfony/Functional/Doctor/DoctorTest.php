<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctor;

use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Command\DoctorCommand;
use App\Doctrine\TenantProvider;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Tests\Fixture\Algorithms;
use DateTimeImmutable;
use App\Doctor\Finding;
use App\Doctor\NotificationsLanePatience;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\KernelInterface;

final class DoctorTest extends KernelTestCase
{
    private const string OWN_LANE = 'test_own_notifications_lane';

    protected function tearDown(): void
    {
        if (self::$booted) {
            new Filesystem()->remove(self::string(self::getContainer()->getParameter('kernel.cache_dir')) . '/keys');
        }
        self::ensureKernelShutdown();
    }

    #[Test]
    public function theDoctorPassesOnTheLaneTheProviderWires(): void
    {
        // Given
        self::keysForEveryAlgorithm();

        // When
        $doctor = self::doctor('test');

        // Then
        static::assertSame(Command::SUCCESS, $doctor->getStatusCode(), $doctor->getDisplay());
    }

    #[Test]
    public function thePassingPointSaysHowLongItTriesAndHowLongWhatItSendsLasts(): void
    {
        // Given
        $finding = self::finding('test');

        // When / Then
        static::assertSame(
            [
                true,
                'A logout token is retried on "async_notifications" for 3 minutes 20 seconds and stops being verifiable after 3 minutes 55 seconds, both read from the schedule this provider publishes (App\Messenger\NotificationRetryPolicy): a client that is restarting is reached, and nothing arrives after the "exp" of the token has passed or after the key that signed it has left the JWK Set.',
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    #[Test]
    public function theDoctorFailsOnALaneOfTheApplicationsOwn(): void
    {
        // When
        $doctor = self::doctor(self::OWN_LANE);

        // Then
        static::assertSame(Command::FAILURE, $doctor->getStatusCode(), $doctor->getDisplay());
    }

    #[Test]
    public function theFailingPointNamesTheTransportAndBothLengthsOfTime(): void
    {
        // Given
        $finding = self::finding(self::OWN_LANE);

        // When / Then
        static::assertSame(
            [
                false,
                'This deployment retries a logout token on the transport "own_notifications" for 10 minutes. One stops being verifiable after 3 minutes 55 seconds, which is how far ahead its "exp" is set and how long the key that signed it stays in the JWK Set, both read from the schedule this provider publishes (App\Messenger\NotificationRetryPolicy); that transport is retried by Symfony\Component\Messenger\Retry\MultiplierRetryStrategy instead.',
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    #[Test]
    public function theFailingPointSaysWhatItCostsAndWhatToDo(): void
    {
        // Given
        $finding = self::finding(self::OWN_LANE);

        // When / Then
        static::assertSame(
            [
                'What it costs: a user who signs out stays signed in on a client that was being retried, that client refusing a token whose "exp" has passed or whose signing key its JWK Set no longer publishes after 3 minutes 55 seconds. It shows after a key rotation or after a client restarts, it is never visible in a browser, and no test of a deployment covers it, every lane being synchronous in a test environment.',
                NotificationsLanePatience::WHAT_TO_DO,
            ],
            [$finding->lines[1] ?? null, $finding->lines[2] ?? null],
        );
    }

    private static function doctor(string $environment): CommandTester
    {
        $application = new Application(self::reboot($environment));
        $application->setAutoExit(false);
        $tester = new CommandTester($application->find(DoctorCommand::NAME));
        $tester->execute([]);

        return $tester;
    }

    private static function finding(string $environment): Finding
    {
        self::reboot($environment);
        $check = self::getContainer()->get('test.beffroi.notifications_lane');
        static::assertInstanceOf(NotificationsLanePatience::class, $check);

        return $check->finding();
    }

    /**
     * The clients the test kernel declares are signed for with each of them.
     */
    private static function keysForEveryAlgorithm(): void
    {
        self::reboot('test');
        $tenant = self::getContainer()->get('test.beffroi.tenant_provider');
        static::assertInstanceOf(TenantProvider::class, $tenant);
        $takeOver = self::getContainer()->get('test.beffroi.key_take_over');
        static::assertInstanceOf(KeyTakeOver::class, $takeOver);
        foreach (Algorithms::all()->all() as $algorithm) {
            $takeOver->rotate($tenant->provide(), $algorithm, new RequestContext(new DateTimeImmutable(), '203.0.113.7', 'beffroi:doctor'));
        }
        // The database is the one the suite left, whose last test may have taken the derivation of the tenant away.
        $derivations = self::getContainer()->get(BlindIndexDerivations::class);
        static::assertInstanceOf(BlindIndexDerivations::class, $derivations);
        $derivations->record($tenant->provide(), 0, 0);
    }

    private static function string(mixed $value): string
    {
        static::assertIsString($value);

        return $value;
    }

    private static function reboot(string $environment): KernelInterface
    {
        self::ensureKernelShutdown();

        return self::bootKernel([
            'environment' => $environment,
        ]);
    }
}
