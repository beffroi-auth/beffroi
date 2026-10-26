<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\Type;

use Beffroi\Bundle\Doctrine\Type\UserSourceType;
use Beffroi\Core\Domain\Identity\UserSource;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0002: the source that created a person, one JSON column, and a null column for a local one,
 * which is what every person the table held before the column came reads as.
 */
final class UserSourceTypeTest extends TestCase
{
    private const string DOCUMENT = '{"provider":"https://idp.acme.example/saml","claims":["email","given_name"]}';

    #[Test]
    public function anUpstreamSourceGoesToTheDatabaseAsItsDocument(): void
    {
        // Given
        $source = UserSource::upstream('https://idp.acme.example/saml', ['email', 'given_name']);

        // When
        $written = new UserSourceType()->convertToDatabaseValue($source, new SQLitePlatform());

        // Then
        static::assertSame(self::DOCUMENT, $written);
    }

    #[Test]
    public function anUpstreamSourceComesBackEqual(): void
    {
        // When
        $read = new UserSourceType()->convertToPHPValue(self::DOCUMENT, new SQLitePlatform());

        // Then
        static::assertEquals(UserSource::upstream('https://idp.acme.example/saml', ['email', 'given_name']), $read);
    }

    #[Test]
    public function aLocalSourceIsANullColumn(): void
    {
        // When / Then
        static::assertNull(new UserSourceType()->convertToDatabaseValue(UserSource::local(), new SQLitePlatform()));
    }

    #[Test]
    public function aNullColumnIsALocalSource(): void
    {
        // When
        $read = new UserSourceType()->convertToPHPValue(null, new SQLitePlatform());

        // Then
        static::assertTrue($read->isLocal());
    }
}
