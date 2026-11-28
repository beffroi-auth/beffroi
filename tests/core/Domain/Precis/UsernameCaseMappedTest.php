<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Precis;

use Beffroi\Core\Domain\Precis\UsernameCaseMapped;
use Beffroi\Core\Exception\UsernameRefusedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class UsernameCaseMappedTest extends TestCase
{
    /**
     * RFC 8265 §3.3.4, §3.3.1, §3.6
     */
    #[Test]
    #[DataProvider('provideUsernamesThatCompareEqual')]
    public function twoUsernamesWhoseEnforcedFormsAreIdenticalCompareEqual(string $one, string $other): void
    {
        // When / Then
        static::assertSame(UsernameCaseMapped::enforce($one), UsernameCaseMapped::enforce($other));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUsernamesThatCompareEqual(): iterable
    {
        yield 'the case of a Latin letter' => ['Alice', 'alice'];
        yield 'the case of an address' => ['Juliet@Example.com', 'juliet@example.com'];
        yield 'a capital and a small sigma, examples 5 and 6 of RFC 8265 §3.6' => ['Σ', 'σ'];
        yield 'the case of a Cyrillic word' => ['КИРИЛЛ', 'кирилл'];
        yield 'a capital sigma that ends a word and a final sigma' => ['ΟΔΥΣΣΕΥΣ', 'οδυσσευς'];
        yield 'fullwidth Latin letters' => ["\u{FF41}\u{FF4C}\u{FF49}\u{FF43}\u{FF45}", 'alice'];
        yield 'a halfwidth Katakana letter' => ["\u{FF76}", "\u{30AB}"];
        yield 'an e and a combining acute accent, and the precomposed e with acute' => ["jose\u{0301}", "jos\u{00E9}"];
        yield 'a dot below and a circumflex combined in either order' => ["e\u{0323}\u{0302}", "e\u{0302}\u{0323}"];
    }

    /**
     * RFC 8265 §3.3.4, §3.6
     */
    #[Test]
    #[DataProvider('provideUsernamesThatDoNotCompareEqual')]
    public function twoUsernamesWhoseEnforcedFormsDifferAreTwo(string $one, string $other): void
    {
        // When / Then
        static::assertNotSame(UsernameCaseMapped::enforce($one), UsernameCaseMapped::enforce($other));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUsernamesThatDoNotCompareEqual(): iterable
    {
        yield 'a double s and an eszett, examples 2 and 3 of RFC 8265 §3.6' => ['fussball', 'fußball'];
        yield 'a capital sigma alone and a final sigma, examples 5 and 7' => ['Σ', 'ς'];
        yield 'a small sigma and a final sigma, examples 6 and 7' => ['σ', 'ς'];
        yield 'a Cyrillic a and a Latin a, which PRECIS does not join' => ["\u{0430}lice", 'alice'];
        yield 'a dotless i and an i' => ["\u{0131}", 'i'];
    }

    /**
     * RFC 8265 §3.3.2, §3.3.3, §3.6, RFC 8264 §4.2
     */
    #[Test]
    #[DataProvider('provideUsernamesTheProfileAdmits')]
    public function aUsernameTheProfileAdmitsIsEnforcedToItsForm(string $username, string $enforced): void
    {
        // When / Then
        static::assertSame($enforced, UsernameCaseMapped::enforce($username));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUsernamesTheProfileAdmits(): iterable
    {
        yield 'an address, example 1 of RFC 8265 §3.6' => ['juliet@example.com', 'juliet@example.com'];
        yield 'example 2' => ['fussball', 'fussball'];
        yield 'an eszett, example 3' => ['fußball', 'fußball'];
        yield 'a small pi, example 4' => ['π', 'π'];
        yield 'a capital sigma, example 5' => ['Σ', 'σ'];
        yield 'a small sigma, example 6' => ['σ', 'σ'];
        yield 'a final sigma, example 7' => ['ς', 'ς'];
        yield 'a Greek word' => ['Ελληνικά', 'ελληνικά'];
        yield 'a Cyrillic word' => ['Кирилл', 'кирилл'];
        yield 'Han ideographs' => ['張偉', '張偉'];
        yield 'a Hebrew word, right to left' => ['שלום', 'שלום'];
        yield 'an Arabic word, right to left' => ['مرحبا', 'مرحبا'];
        yield 'printable ASCII whole' => ['!"#$%&\'()*+,-./0123456789:;<=>?@AZ[\]^_`az{|}~', '!"#$%&\'()*+,-./0123456789:;<=>?@az[\]^_`az{|}~'];
        yield 'a capital I with a dot above, lowercased to an i and a combining dot' => ["\u{0130}", "i\u{0307}"];
    }

    /**
     * RFC 8265 §3.3.2, §3.3.3, §3.6, RFC 8264 §4.2.3, §4.2.4, RFC 5893 §2
     */
    #[Test]
    #[DataProvider('provideUsernamesTheProfileRefuses')]
    public function aUsernameTheProfileRefusesIsRefused(string $username): void
    {
        // Then
        $this->expectException(UsernameRefusedException::class);

        // When
        UsernameCaseMapped::enforce($username);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUsernamesTheProfileRefuses(): iterable
    {
        yield 'a space, example 8 of RFC 8265 §3.6' => ['foo bar'];
        yield 'nothing, example 9' => [''];
        yield 'a Roman numeral, which has a compatibility equivalent, example 10' => ["henry\u{2163}"];
        yield 'a symbol, example 11' => ['∞'];
        yield 'an emoji' => ["alice\u{1F600}"];
        yield 'a currency sign outside ASCII' => ["alice\u{20AC}"];
        yield 'a punctuation mark outside ASCII' => ["alice\u{2014}bob"];
        yield 'a no-break space' => ["alice\u{00A0}bob"];
        yield 'an ideographic space, width mapped to a space' => ["alice\u{3000}bob"];
        yield 'a control character' => ["alice\u{0007}"];
        yield 'a soft hyphen, ignorable' => ["al\u{00AD}ice"];
        yield 'a noncharacter' => ["alice\u{FDD0}"];
        yield 'a code point of private use' => ["alice\u{E000}"];
        yield 'an old Hangul jamo' => ["\u{1100}"];
        yield 'a code point no version of Unicode assigns yet' => ["alice\u{40000}"];
        yield 'a zero width joiner after no virama' => ["al\u{200D}ice"];
        yield 'a Hebrew word followed by Latin letters, against condition 2 of the Bidi Rule' => ['שלוםabc'];
        yield 'a Hebrew word that begins with a European digit, against condition 1' => ['1שלום'];
        yield 'European and Arabic-Indic digits in an Arabic word, against condition 4' => ["\u{0628}1\u{0662}"];
        yield 'bytes that are no UTF-8' => ["alice\xC3"];
        yield '256 characters' => [str_repeat('a', 256)];
        yield '200 characters whose lowercase is 400' => [str_repeat("\u{0130}", 200)];
    }

    /**
     * RFC 8264 §4.2, RFC 5892 Appendix A, RFC 5893 §2
     */
    #[Test]
    #[DataProvider('provideRefusals')]
    public function aRefusalSaysWhatTheUsernameBreaks(string $username, string $message): void
    {
        // Then
        $this->expectException(UsernameRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        UsernameCaseMapped::enforce($username);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'a code point of no letter or digit' => [
            "alice\u{1F600}",
            'A username holds letters and digits of any script and printable ASCII, and U+1F600 is none of them (RFC 8264 §4.2).',
        ];
        yield 'a code point of a contextual rule where it does not allow it' => [
            "al\u{200D}ice",
            'A username holds U+200D only where its contextual rule allows it (RFC 5892 Appendix A).',
        ];
        yield 'the Bidi Rule' => ['שלוםabc', 'A username written right to left follows the Bidi Rule (RFC 5893 §2).'];
        yield 'the length' => [str_repeat('a', 256), 'A username is 1 to 255 characters long.'];
        yield 'the encoding' => ["alice\xC3", 'A username is written in UTF-8.'];
    }
}
