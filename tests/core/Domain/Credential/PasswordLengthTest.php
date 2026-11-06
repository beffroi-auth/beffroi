<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * NIST SP 800-63B §3.1.1.2, Decision 0025
 */
final class PasswordLengthTest extends TestCase
{
    /**
     * NIST SP 800-63B §3.1.1.2
     */
    #[Test]
    public function aPasswordThatIsTheWholeOfALoginReachesFifteenCharacters(): void
    {
        // When / Then
        static::assertSame(15, PasswordLength::under(new SingleFactor())->minimum);
    }

    /**
     * Architecture §9
     */
    #[Test]
    public function aPasswordASecondFactorIsReadBesideReachesTwelveCharacters(): void
    {
        // When / Then
        static::assertSame(12, PasswordLength::under(new TwoFactors())->minimum);
    }

    #[Test]
    public function aFloorThatReadsNoPasswordIsAnsweredTheShorterLength(): void
    {
        // When / Then
        static::assertSame(12, PasswordLength::under(new PhishingResistant())->minimum);
    }

    /**
     * §3.1.1.2
     */
    #[Test]
    public function fifteenMultibyteCharactersReachFifteen(): void
    {
        // Given
        $length = PasswordLength::under(new SingleFactor());

        // When / Then
        static::assertTrue($length->reachedBy(str_repeat('é', 15)));
    }

    #[Test]
    public function oneCharacterShortDoesNotReachIt(): void
    {
        // Given
        $length = PasswordLength::under(new SingleFactor());

        // When / Then
        static::assertFalse($length->reachedBy(str_repeat('é', 14)));
    }
}
