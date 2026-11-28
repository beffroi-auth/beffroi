<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Precis;

use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Precis\OpaqueString;
use Beffroi\Core\Exception\PasswordRefusedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class OpaqueStringTest extends TestCase
{
    /**
     * RFC 8265 §4.2.2, §4.3
     */
    #[Test]
    #[DataProvider('providePasswordsTheProfileAdmits')]
    public function aPasswordTheProfileAdmitsIsEnforcedToItsForm(string $password, string $enforced): void
    {
        // When / Then
        static::assertSame($enforced, OpaqueString::enforce($password));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providePasswordsTheProfileAdmits(): iterable
    {
        yield 'a space, example 12 of RFC 8265 §4.3' => ['correct horse battery staple', 'correct horse battery staple'];
        yield 'capitals, kept by rule 3, example 13' => ['Correct Horse Battery Staple', 'Correct Horse Battery Staple'];
        yield 'non-ASCII letters, example 14' => ['πßå', 'πßå'];
        yield 'a symbol, example 15' => ['Jack of ♦s', 'Jack of ♦s'];
        yield 'an ogham space mark mapped to a space by rule 2, example 16' => ["foo\u{1680}bar", 'foo bar'];
        yield 'a no-break space mapped to a space by rule 2' => ["foo\u{00A0}bar", 'foo bar'];
        yield 'a narrow no-break space mapped to a space by rule 2' => ["foo\u{202F}bar", 'foo bar'];
        yield 'an ideographic space mapped to a space by rule 2' => ["foo\u{3000}bar", 'foo bar'];
        yield 'an e and a combining acute accent composed by rule 4' => ["jose\u{0301}", "jos\u{00E9}"];
        yield 'a dot below and a circumflex ordered by rule 4' => ["e\u{0302}\u{0323}", "\u{1EC7}"];
        yield 'a Greek question mark, canonically a semicolon, rule 4' => ["a\u{037E}b", 'a;b'];
        yield 'an angstrom sign, canonically a capital A with a ring, rule 4' => ["\u{212B}", "\u{00C5}"];
        yield 'a fullwidth letter, kept by rule 1' => ["\u{FF41}", "\u{FF41}"];
        yield 'a ligature, kept by Normalization Form C' => ["\u{FB01}", "\u{FB01}"];
        yield 'Hebrew followed by Latin letters, which no directionality rule refuses, rule 5' => ['שלוםabc', 'שלוםabc'];
        yield 'an emoji' => ["\u{1F600}", "\u{1F600}"];
        yield 'as many bytes as a hasher takes' => [str_repeat('a', OpaqueString::MAXIMUM_BYTES), str_repeat('a', OpaqueString::MAXIMUM_BYTES)];
    }

    /**
     * RFC 8265 §4.2.3, §4.3
     */
    #[Test]
    #[DataProvider('providePasswordsTheProfileDoesNotJoin')]
    public function twoPasswordsWhoseEnforcedFormsDifferAreTwo(string $one, string $other): void
    {
        // When / Then
        static::assertNotSame(OpaqueString::enforce($one), OpaqueString::enforce($other));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providePasswordsTheProfileDoesNotJoin(): iterable
    {
        yield 'examples 12 and 13, which differ by case' => ['correct horse battery staple', 'Correct Horse Battery Staple'];
        yield 'a fullwidth letter and its ASCII letter' => ["\u{FF41}", 'a'];
        yield 'a ligature and its two letters' => ["\u{FB01}", 'fi'];
        yield 'an eszett and a double s' => ['ß', 'ss'];
        yield 'a Cyrillic a and a Latin a' => ["\u{0430}", 'a'];
        yield 'a space and no space' => ['foo bar', 'foobar'];
    }

    /**
     * RFC 8264 §7
     */
    #[Test]
    #[DataProvider('providePasswordsInAnotherForm')]
    public function theEnforcedFormIsItsOwnEnforcedForm(string $password): void
    {
        // Given
        $enforced = OpaqueString::enforce($password);

        // When / Then
        static::assertSame($enforced, OpaqueString::enforce($enforced));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePasswordsInAnotherForm(): iterable
    {
        yield 'an ogham space mark, example 16' => ["foo\u{1680}bar"];
        yield 'a decomposed letter' => ["jose\u{0301}"];
        yield 'a Greek question mark' => ["a\u{037E}b"];
        yield 'a letter Normalization Form C decomposes' => ["\u{0958}"];
    }

    /**
     * RFC 8265 §4.2.1, §4.2.2, RFC 8264 §4.3.2, §4.3.3, RFC 5892 §2.9, Appendix A.2
     */
    #[Test]
    #[DataProvider('provideStringsTheClassRefusesBeforeNormalizationFormC')]
    public function theClassIsHeldToWhatWasTypedBeforeNormalizationFormC(string $typed): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);

        // When
        OpaqueString::enforce($typed);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStringsTheClassRefusesBeforeNormalizationFormC(): iterable
    {
        yield 'Korean in Normalization Form D, whose conjoining jamo are old Hangul jamo' => ["\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}"];
        yield 'a zero width joiner after a nukta, which Normalization Form C moves after the virama' => ["\u{0915}\u{094D}\u{093C}\u{200D}\u{0937}"];
    }

    /**
     * RFC 8264 §7, §4.3.1, RFC 5892 Appendix A.2
     */
    #[Test]
    #[DataProvider('provideTheirNormalizationFormC')]
    public function theirNormalizationFormCIsAdmitted(string $composed): void
    {
        // When / Then
        static::assertSame($composed, OpaqueString::enforce($composed));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTheirNormalizationFormC(): iterable
    {
        yield 'Korean in Normalization Form C' => ["\u{D55C}\u{AE00}"];
        yield 'a zero width joiner after the virama, the nukta before it' => ["\u{0915}\u{093C}\u{094D}\u{200D}\u{0937}"];
    }

    /**
     * RFC 8265 §4.1, §4.2.1, §4.3, RFC 8264 §4.3.3, §4.3.4
     */
    #[Test]
    #[DataProvider('providePasswordsTheProfileRefuses')]
    public function aPasswordTheProfileRefusesIsRefusedWithItsReason(string $password, PasswordRefusal $refusal): void
    {
        // When
        try {
            OpaqueString::enforce($password);
            static::fail('The profile admitted what it refuses.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame($refusal, $exception->refusal);
        }
    }

    /**
     * @return iterable<string, array{string, PasswordRefusal}>
     */
    public static function providePasswordsTheProfileRefuses(): iterable
    {
        yield 'nothing, example 17 of RFC 8265 §4.3' => ['', PasswordRefusal::TooShort];
        yield 'a tabulation, example 18' => ["my cat is a \u{0009}by", PasswordRefusal::DisallowedCharacter];
        yield 'a soft hyphen, ignorable' => ["correct\u{00AD}horse", PasswordRefusal::DisallowedCharacter];
        yield 'a zero width space, ignorable' => ["correct\u{200B}horse", PasswordRefusal::DisallowedCharacter];
        yield 'the variation selector of an emoji, ignorable' => ["I\u{2764}\u{FE0F}NY", PasswordRefusal::DisallowedCharacter];
        yield 'a zero width joiner between two emoji' => ["\u{1F468}\u{200D}\u{1F469}", PasswordRefusal::DisallowedCharacter];
        yield 'a code point of private use' => ["correct\u{E000}", PasswordRefusal::DisallowedCharacter];
        yield 'a code point no version of Unicode assigns yet' => ["correct\u{40000}", PasswordRefusal::DisallowedCharacter];
        yield 'bytes that are no UTF-8' => ["correct\xC3", PasswordRefusal::DisallowedCharacter];
        yield 'one byte more than a hasher takes' => [str_repeat('a', OpaqueString::MAXIMUM_BYTES + 1), PasswordRefusal::TooLong];
        yield 'bytes Normalization Form C makes more than a hasher takes' => [str_repeat("\u{0958}", 1365), PasswordRefusal::TooLong];
    }

    /**
     * RFC 8265 §4.1, RFC 8264 §4.3
     */
    #[Test]
    #[DataProvider('provideRefusals')]
    public function aRefusalSaysWhatThePasswordBreaksAndNoneOfItsCharacters(string $password, string $message): void
    {
        // Then
        $this->expectException(PasswordRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        OpaqueString::enforce($password);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'a code point the class refuses' => [
            "secret\u{0007}",
            'A password holds no control character, and no code point that Unicode leaves unassigned, ignorable or to private use (RFC 8264 §4.3).',
        ];
        yield 'nothing' => ['', 'A password is never empty (RFC 8265 §4.1).'];
        yield 'the length' => [str_repeat('a', OpaqueString::MAXIMUM_BYTES + 1), 'A password is at most 4096 bytes long.'];
        yield 'the encoding' => ["secret\xC3", 'A password is written in UTF-8.'];
    }
}
