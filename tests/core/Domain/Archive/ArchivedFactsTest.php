<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
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
        $act = self::act(new AnAdministrator(new Subject('mallory-subject')));

        // When
        $facts = ArchivedFacts::act($act);

        // Then
        static::assertSame(
            [
                'act' => 'administration.person_read',
                'occurred_at' => '2026-09-15T10:00:00+00:00',
                'client' => null,
                'from' => null,
                'author' => ['kind' => 'administrator'],
            ],
            $facts,
        );
    }

    /**
     * Decision 0066
     *
     * @param array<string, string>|null $archived
     */
    #[Test]
    #[DataProvider('provideAuthorsToldWhoTheyAre')]
    public function anActOfAnAuthorNotToldByTheirRoleIsArchivedWithWhoTheyAreAndWhereItCameFrom(?AuthorInterface $author, ?array $archived): void
    {
        // Given
        $act = self::act($author);

        // When
        $facts = ArchivedFacts::act($act);

        // Then
        static::assertSame(
            ['tui-of-mallory', ArchivedFacts::context(Fixtures::context()), $archived],
            [$facts['client'], $facts['from'], $facts['author']],
        );
    }

    /**
     * @return iterable<string, array{AuthorInterface|null, array<string, string>|null}>
     */
    public static function provideAuthorsToldWhoTheyAre(): iterable
    {
        yield 'the person' => [new ThePerson(), ['kind' => 'person']];
        yield 'a client' => [new AClient('oidc-demo'), ['kind' => 'client', 'client_id' => 'oidc-demo']];
        yield 'a directory, by its name' => [new ADirectory('Entra ID'), ['kind' => 'directory', 'name' => 'Entra ID']];
        yield 'the host' => [new TheHost(), ['kind' => 'host']];
        yield 'nobody, written before acts named the kind of their author' => [null, null];
    }

    #[Test]
    public function anActAsWrittenNamesTheAdministratorWhoDidIt(): void
    {
        // When
        $facts = ArchivedFacts::actAsWritten(self::act(new AnAdministrator(new Subject('mallory-subject'))));

        // Then
        static::assertSame(
            ['tui-of-mallory', ArchivedFacts::context(Fixtures::context()), ['kind' => 'administrator', 'subject' => 'mallory-subject']],
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

    private static function act(?AuthorInterface $author): JournalEntry
    {
        return new JournalEntry(
            Uuid::v7(),
            Fixtures::tenant(),
            'administration.person_read',
            Fixtures::now(),
            Fixtures::context(),
            new Subject('alice-subject'),
            'tui-of-mallory',
            $author,
        );
    }
}
