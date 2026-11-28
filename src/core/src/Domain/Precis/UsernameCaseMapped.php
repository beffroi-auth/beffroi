<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use Beffroi\Core\Domain\Encoding\PlainText;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Exception\UsernameRefusedException;
use IntlChar;
use function in_array;
use function is_string;
use function mb_check_encoding;
use function mb_strlen;
use Normalizer;
use function sprintf;
use Transliterator;

/**
 * RFC 8265 §3.3, the profile RFC 7644 §5 requires of a userName: two usernames are the same when their enforced forms
 * are identical octet for octet (§3.3.4).
 */
final readonly class UsernameCaseMapped
{
    /**
     * The length is bounded before any Unicode work, on what was written as on what it becomes.
     *
     * @throws UsernameRefusedException
     */
    public static function enforce(string $username): string
    {
        if (! mb_check_encoding($username, 'UTF-8')) {
            throw new UsernameRefusedException('A username is written in UTF-8.');
        }
        self::assertLength($username);

        return (
            Reapplication::settled(
                $username,
                self::applied(...),
            ) ?? throw new UsernameRefusedException('A username whose form does not settle is refused (RFC 8264 §7).')
        );
    }

    /**
     * The enforced form, or the username as written when the profile refuses it. No person is created or renamed under
     * a refused username; one written before the profile applied is compared as written, an exception that ends with
     * 1.0.0.
     */
    public static function comparisonForm(string $username): string
    {
        try {
            return self::enforce($username);
        } catch (UsernameRefusedException) {
            return $username;
        }
    }

    /**
     * RFC 8265 §3.3.2, then §3.3.3.
     *
     * @throws UsernameRefusedException
     */
    private static function applied(string $username): string
    {
        $typed = CodePoints::of($username);
        [$prepared, $from] = self::widthMapped($typed);
        $refused = IdentifierClass::firstRefused($prepared);
        if ($refused !== null) {
            throw self::refusal($prepared[$refused], $typed[$from[$refused]]);
        }
        $normalized = Normalizer::normalize(self::lowercased(CodePoints::text($prepared)), Normalizer::FORM_C);
        if (! is_string($normalized)) {
            throw new LogicException('The intl extension could not bring a username to Normalization Form C.');
        }
        $codePoints = CodePoints::of($normalized);
        if (BidiRule::isRightToLeft($codePoints) && ! BidiRule::holds($codePoints)) {
            throw new UsernameRefusedException('A username written right to left follows the Bidi Rule (RFC 5893 §2).');
        }
        self::assertLength($normalized);

        return $normalized;
    }

    /**
     * RFC 8265 §3.3.1 rule 1: a code point of the Decomposition_Type Wide or Narrow mapped to its decomposition.
     *
     * @param list<int> $codePoints
     *
     * @return array{list<int>, list<int>} the code points mapped, and the position of the one each was mapped from
     */
    private static function widthMapped(array $codePoints): array
    {
        $mapped = [];
        $from = [];
        foreach ($codePoints as $position => $codePoint) {
            $type = IntlChar::getIntPropertyValue($codePoint, IntlChar::PROPERTY_DECOMPOSITION_TYPE);
            $decomposition = in_array($type, [IntlChar::DT_WIDE, IntlChar::DT_NARROW], true)
                ? Normalizer::getRawDecomposition(IntlChar::chr($codePoint) ?? '', Normalizer::FORM_KC)
                : null;
            foreach (is_string($decomposition) ? CodePoints::of($decomposition) : [$codePoint] as $kept) {
                $mapped[] = $kept;
                $from[] = $position;
            }
        }

        return [$mapped, $from];
    }

    /**
     * RFC 8265 §3.3.1 rule 3: the toLowerCase() of the Unicode Standard, the context of a final sigma included,
     * which the Lower transliterator of ICU applies.
     */
    private static function lowercased(string $username): string
    {
        /** @var Transliterator|null $lower */
        static $lower = null;
        $lower ??= Transliterator::create('Lower') ?? throw new LogicException('The intl extension has no Lower transliterator.');
        $lowercased = $lower->transliterate($username);
        if ($lowercased === false) {
            throw new LogicException('The intl extension could not lowercase a username.');
        }

        return $lowercased;
    }

    /**
     * RFC 8265 §3.1: never zero bytes, after the rules as before them.
     *
     * @throws UsernameRefusedException
     */
    private static function assertLength(string $username): void
    {
        $length = mb_strlen($username);
        if ($length === 0 || $length > PlainText::MAX_LENGTH) {
            throw new UsernameRefusedException(sprintf('A username is 1 to %d characters long.', PlainText::MAX_LENGTH));
        }
    }

    /**
     * Names the code point as it was typed, the one it was mapped to being what the class refused.
     */
    private static function refusal(int $mapped, int $typed): UsernameRefusedException
    {
        return new UsernameRefusedException(match (DerivedProperty::of($mapped)) {
            DerivedPropertyValue::Contextj, DerivedPropertyValue::Contexto => sprintf(
                'A username holds U+%04X only where its contextual rule allows it (RFC 5892 Appendix A).',
                $typed,
            ),
            default => sprintf(
                'A username holds letters and digits of any script and printable ASCII, and U+%04X is none of them (RFC 8264 §4.2).',
                $typed,
            ),
        });
    }
}
