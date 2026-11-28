<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Precis\OpaqueString;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Exception\PasswordRefusedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use function substr;

/**
 * NIST SP 800-63B §3.1.1.2, CVE-2013-1443, RFC 8265 §4.2
 */
final class PlainPasswordTest extends TestCase
{
    private const string A_PASSWORD = 'correct horse battery staple';

    private const string THIRTEEN_LETTERS = 'mindfulbakery';

    #[Test]
    public function aPasswordLongAndVariedEnoughIsHeld(): void
    {
        // When / Then
        static::assertSame(self::A_PASSWORD, new PlainPassword(self::A_PASSWORD, self::alone())->value);
    }

    /**
     * NIST SP 800-63B §3.1.1.2
     */
    #[Test]
    public function thirteenCharactersAreRefusedWhereAPasswordSignsSomebodyInAlone(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password is at least 15 characters long.');

        // When
        new PlainPassword(self::THIRTEEN_LETTERS, self::alone());
    }

    /**
     * Architecture §9
     */
    #[Test]
    public function elevenCharactersAreRefusedWhereASecondFactorIsReadBeside(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password is at least 12 characters long.');

        // When
        new PlainPassword('Tr0ub4dor&3', self::withASecondFactor());
    }

    #[Test]
    public function twelveMultibyteCharactersAreNotTooShortWhereTwelveIsAsked(): void
    {
        // Given
        $password = str_repeat('é', 12);

        // When
        try {
            new PlainPassword($password, self::withASecondFactor());
            static::fail('A password of one repeated character is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::TooWeak, $exception->refusal);
        }
    }

    #[Test]
    public function fourThousandAndNinetySixBytesAreAccepted(): void
    {
        // Given
        $password = self::bytes(OpaqueString::MAXIMUM_BYTES);

        // When / Then
        static::assertSame(OpaqueString::MAXIMUM_BYTES, strlen(new PlainPassword($password, self::alone())->value));
    }

    #[Test]
    public function oneByteMoreIsRefused(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password is at most 4096 bytes long.');

        // When
        new PlainPassword(self::bytes(OpaqueString::MAXIMUM_BYTES + 1), self::alone());
    }

    /**
     * §3.1.1.2
     */
    #[Test]
    #[DataProvider('provideGuessablePasswords')]
    public function aGuessablePasswordIsRefused(string $password): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password this short of length and of alphabet is guessed: make it longer, or several words.');

        // When
        new PlainPassword($password, self::withASecondFactor());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideGuessablePasswords(): iterable
    {
        yield 'twelve letters and nothing else' => ['abcdefghijkl'];
        yield 'one character repeated' => [str_repeat('a', 24)];
        yield 'a word written twice' => ['passwordpassword'];
        yield 'a euro sign repeated' => [str_repeat('€', 15)];
        yield 'an emoji repeated' => [str_repeat('😀', 12)];
    }

    /**
     * RFC 8265 §4.2.2
     */
    #[Test]
    public function theValueIsTheFormTheProfileEnforces(): void
    {
        // When / Then
        static::assertSame('correct horse battery staple', new PlainPassword("correct\u{00A0}horse battery\u{1680}staple", self::alone())->value);
    }

    /**
     * RFC 8265 §4.1, §4.3, RFC 8264 §4.3.3
     */
    #[Test]
    #[DataProvider('providePasswordsTheProfileRefuses')]
    public function aPasswordTheProfileRefusesIsRefusedForItsCharacter(string $password): void
    {
        // When
        try {
            new PlainPassword($password, self::alone());
            static::fail('A password the profile refuses was held.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::DisallowedCharacter, $exception->refusal);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePasswordsTheProfileRefuses(): iterable
    {
        yield 'a tabulation, example 18 of RFC 8265 §4.3' => ["my cat is a \u{0009}by and a long one"];
        yield 'a letter padded with zero-width spaces' => ['a' . str_repeat("\u{200B}", 14)];
        yield 'an emoji followed by its variation selector' => ["I love New York \u{2764}\u{FE0F}"];
    }

    /**
     * RFC 8265 §4.1, NIST SP 800-63B §3.1.1.2
     */
    #[Test]
    public function anEmptyPasswordIsTooShort(): void
    {
        // When
        try {
            new PlainPassword('', self::alone());
            static::fail('An empty password was held.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::TooShort, $exception->refusal);
        }
    }

    /**
     * NIST SP 800-63B §3.1.1.2, RFC 8265 §4.2.2 rule 4
     */
    #[Test]
    public function theLengthIsCountedOnTheEnforcedForm(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password is at least 15 characters long.');

        // When
        new PlainPassword(str_repeat("e\u{0301}", 8) . 'wxyz', self::alone());
    }

    /**
     * NIST SP 800-63B §3.1.1.2, RFC 8265 §4.2.2 rule 2
     */
    #[Test]
    public function theStrengthIsMeasuredOnTheEnforcedForm(): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs('A password this short of length and of alphabet is guessed: make it longer, or several words.');

        // When
        new PlainPassword(str_repeat("abcd\u{00A0}", 3) . 'a', self::withASecondFactor());
    }

    #[Test]
    #[DataProvider('provideAcceptedPasswords')]
    public function aPasswordPastEveryRuleOfItsFloorIsHeld(string $password): void
    {
        // When / Then
        static::assertSame($password, new PlainPassword($password, self::withASecondFactor())->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedPasswords(): iterable
    {
        yield 'four words of letters only' => [self::A_PASSWORD];
        yield 'thirteen letters and nothing else' => [self::THIRTEEN_LETTERS];
        yield 'twelve of every alphabet' => ['Tr0ub4dor&31'];
    }

    /**
     * RFC 8265 §4.2.3
     */
    #[Test]
    public function aPasswordTypedAgainInAnotherFormIsConfirmed(): void
    {
        // Given
        $password = new PlainPassword("correct\u{00A0}horse battery staple", self::alone());

        // When / Then
        static::assertTrue($password->confirmedBy("correct horse battery\u{3000}staple"));
    }

    /**
     * RFC 8265 §4.2.3, §4.1
     */
    #[Test]
    #[DataProvider('provideConfirmationsOfAnotherPassword')]
    public function aPasswordTypedAgainAsAnotherOneIsNotConfirmed(string $again): void
    {
        // Given
        $password = new PlainPassword(self::A_PASSWORD, self::alone());

        // When / Then
        static::assertFalse($password->confirmedBy($again));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideConfirmationsOfAnotherPassword(): iterable
    {
        yield 'another password' => ['correct horse battery stable'];
        yield 'the same letters in capitals, rule 3 of RFC 8265 §4.2.2' => ['Correct Horse Battery Staple'];
        yield 'what the profile refuses' => ["correct horse battery staple\u{0009}"];
    }

    /**
     * Decision 0025
     */
    private static function alone(): PasswordLength
    {
        return PasswordLength::under(new SingleFactor());
    }

    private static function withASecondFactor(): PasswordLength
    {
        return PasswordLength::under(new TwoFactors());
    }

    private static function bytes(int $length): string
    {
        return substr(str_repeat(self::A_PASSWORD . ' ', 1 + (int) ($length / strlen(self::A_PASSWORD))), 0, $length);
    }
}
