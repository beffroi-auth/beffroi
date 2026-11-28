<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ArchivedFactsTest extends TestCase
{
    /**
     * Decision 0038, RGPD article 15(4)
     */
    #[Test]
    public function anActAnAdministratorDidIsArchivedByTheirRoleAlone(): void
    {
        // Given
        $act = self::act(new Subject('mallory-subject'));

        // When
        $facts = ArchivedFacts::act($act);

        // Then
        static::assertSame(
            [
                'act' => 'administration.person_read',
                'occurred_at' => '2026-09-15T10:00:00+00:00',
                'client' => null,
                'from' => null,
                'author' => 'administrator',
            ],
            $facts,
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function anActAboutItsClientThatAnAdministratorDidKeepsTheClient(): void
    {
        // Given
        $act = self::act(new Subject('mallory-subject'));

        // When
        $facts = ArchivedFacts::act($act, ['administration.person_read']);

        // Then
        static::assertSame(['tui-of-mallory', null, 'administrator'], [$facts['client'], $facts['from'], $facts['author']]);
    }

    #[Test]
    public function anActNoAdministratorDidIsArchivedWithWhereItCameFrom(): void
    {
        // Given
        $act = self::act(null);

        // When
        $facts = ArchivedFacts::act($act);

        // Then
        static::assertSame(
            ['tui-of-mallory', ArchivedFacts::context(Fixtures::context()), null],
            [$facts['client'], $facts['from'], $facts['author']],
        );
    }

    #[Test]
    public function anActAsWrittenNamesTheAdministratorWhoDidIt(): void
    {
        // When
        $facts = ArchivedFacts::actAsWritten(self::act(new Subject('mallory-subject')));

        // Then
        static::assertSame(
            ['tui-of-mallory', ArchivedFacts::context(Fixtures::context()), 'mallory-subject'],
            [$facts['client'], $facts['from'], $facts['author']],
        );
    }

    /**
     * RFC 3339, RGPD article 20
     */
    #[Test]
    public function aMomentIsWrittenInTheShapeOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('2026-09-15T10:00:00+00:00', ArchivedFacts::moment(Fixtures::now()));
    }

    #[Test]
    public function aMomentThisProviderHoldsNoneOfIsNone(): void
    {
        // When / Then
        static::assertNull(ArchivedFacts::moment(null));
    }

    #[Test]
    public function aProvenanceIsTheAddressAndTheUserAgentAsTheyReachedTheProvider(): void
    {
        // When
        $facts = ArchivedFacts::context(Fixtures::context());

        // Then
        static::assertSame(Fixtures::context()->ipAddress, $facts['ip_address']);
        static::assertSame(Fixtures::context()->userAgent, $facts['user_agent']);
        static::assertSame('2026-09-15T10:00:00+00:00', $facts['received_at']);
    }

    #[Test]
    public function aProvenanceThatWasEnrichedCarriesWhereAndWhatFrom(): void
    {
        // Given
        $context = Fixtures::context()
            ->withLocation(new GeoLocation('FR', 'Grand Est', 'Strasbourg', 64476, 'Example Telecom', 48.5839, 7.7455))
            ->withDevice(new Device(DeviceType::Mobile, 'Firefox', '140.0', 'Android', '15'));

        // When
        $facts = ArchivedFacts::context($context);

        // Then
        static::assertSame(
            [
                'country_code' => 'FR',
                'region' => 'Grand Est',
                'city' => 'Strasbourg',
                'autonomous_system_number' => 64476,
                'autonomous_system_organization' => 'Example Telecom',
                'latitude' => 48.5839,
                'longitude' => 7.7455,
            ],
            $facts['location'],
        );
        static::assertSame(
            [
                'type' => 'mobile',
                'browser' => 'Firefox',
                'browser_version' => '140.0',
                'platform' => 'Android',
                'platform_version' => '15',
            ],
            $facts['device'],
        );
    }

    #[Test]
    public function aProvenanceThatWasNotEnrichedCarriesNeither(): void
    {
        // When
        $facts = ArchivedFacts::context(Fixtures::context());

        // Then
        static::assertNull($facts['location']);
        static::assertNull($facts['device']);
    }

    private static function act(?Subject $administrator): JournalEntry
    {
        return new JournalEntry(
            Uuid::v7(),
            Fixtures::tenant(),
            'administration.person_read',
            Fixtures::now(),
            Fixtures::context(),
            new Subject('alice-subject'),
            'tui-of-mallory',
            $administrator,
        );
    }
}
