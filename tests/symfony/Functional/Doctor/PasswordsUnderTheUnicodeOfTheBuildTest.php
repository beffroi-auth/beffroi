<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctor;

use App\Doctor\PasswordsUnderTheUnicodeOfTheBuild;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use IntlChar;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;

final class PasswordsUnderTheUnicodeOfTheBuildTest extends DatabaseTestCase
{
    /**
     * RFC 8264 §13.4, decision 0065
     */
    #[Test]
    public function aProcessUnderTheUnicodeTheTenantWasLastIndexedUnderIsGreen(): void
    {
        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [true, [sprintf('This process reads Unicode %s, as the tenant "%s" was last indexed under.', IntlChar::UNICODE_VERSION, self::tenant()->slug)]],
            [$finding->green, $finding->lines],
        );
    }

    /**
     * RFC 8264 §13.4, decision 0065
     */
    #[Test]
    public function aProcessUnderAnotherUnicodeThanTheTenantWasLastIndexedUnderIsRed(): void
    {
        // Given
        self::entityManager()
            ->getConnection()
            ->executeStatement('UPDATE ' . BlindIndexDerivations::TABLE . " SET unicode_version = '15.1'");

        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [
                false,
                sprintf(
                    'The tenant "%s" was last indexed under Unicode 15.1, and this process reads Unicode %s: a password posed under the one may be refused under the other.',
                    self::tenant()->slug,
                    IntlChar::UNICODE_VERSION,
                ),
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    /**
     * RFC 8264 §13.4
     */
    #[Test]
    public function aTenantThatRecordsNoVersionYetIsGreen(): void
    {
        // Given
        self::entityManager()
            ->getConnection()
            ->executeStatement('DELETE FROM ' . BlindIndexDerivations::TABLE);

        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [true, [sprintf('This process reads Unicode %s, and the tenant "%s" records no version yet.', IntlChar::UNICODE_VERSION, self::tenant()->slug)]],
            [$finding->green, $finding->lines],
        );
    }

    private static function check(): PasswordsUnderTheUnicodeOfTheBuild
    {
        return self::service(PasswordsUnderTheUnicodeOfTheBuild::class, PasswordsUnderTheUnicodeOfTheBuild::class);
    }
}
