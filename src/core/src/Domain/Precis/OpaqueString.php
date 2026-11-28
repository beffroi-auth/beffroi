<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Exception\PasswordRefusedException;
use IntlChar;
use function is_string;
use function mb_check_encoding;
use Normalizer;
use SensitiveParameter;
use function sprintf;
use function strlen;

/**
 * RFC 8265 §4.2, the profile RFC 7644 §5 requires of a password: what is hashed and what is verified is the enforced
 * form (RFC 8265 §8.2).
 */
final readonly class OpaqueString
{
    private const int SPACE = 0x20;

    /**
     * The length is bounded in bytes before any Unicode work, on what was typed as on what it becomes, and no refusal
     * names a code point of the password.
     *
     * @throws PasswordRefusedException
     */
    public static function enforce(#[SensitiveParameter] string $password): string
    {
        self::assertLength($password);
        if (! mb_check_encoding($password, 'UTF-8')) {
            throw new PasswordRefusedException(PasswordRefusal::DisallowedCharacter, 'A password is written in UTF-8.');
        }

        return (
            Reapplication::settled($password, self::applied(...)) ?? throw new PasswordRefusedException(
                PasswordRefusal::DisallowedCharacter,
                'A password whose form does not settle is refused (RFC 8264 §7).',
            )
        );
    }

    /**
     * RFC 8265 §4.2.1, then the rules of §4.2.2 in their order: no width mapping, the additional mapping, no case
     * mapping, Normalization Form C, no directionality rule.
     *
     * @throws PasswordRefusedException
     */
    private static function applied(#[SensitiveParameter] string $password): string
    {
        $codePoints = CodePoints::of($password);
        if (FreeformClass::firstRefused($codePoints) !== null) {
            throw new PasswordRefusedException(
                PasswordRefusal::DisallowedCharacter,
                'A password holds no control character, and no code point that Unicode leaves unassigned, ignorable or to private use (RFC 8264 §4.3).',
            );
        }
        $normalized = Normalizer::normalize(CodePoints::text(self::spacesMapped($codePoints)), Normalizer::FORM_C);
        if (! is_string($normalized)) {
            throw new LogicException('The intl extension could not bring a password to Normalization Form C.');
        }
        self::assertLength($normalized);

        return $normalized;
    }

    /**
     * RFC 8265 §4.2.2 rule 2: a code point of the general category Zs mapped to SPACE (U+0020).
     *
     * @param list<int> $codePoints
     *
     * @return list<int>
     */
    private static function spacesMapped(#[SensitiveParameter] array $codePoints): array
    {
        $mapped = [];
        foreach ($codePoints as $codePoint) {
            $mapped[] = IntlChar::charType($codePoint) === IntlChar::CHAR_CATEGORY_SPACE_SEPARATOR ? self::SPACE : $codePoint;
        }

        return $mapped;
    }

    /**
     * RFC 8265 §4.1: never zero bytes, after the rules as before them; and never more than a hasher takes.
     *
     * @throws PasswordRefusedException
     */
    private static function assertLength(#[SensitiveParameter] string $password): void
    {
        if ($password === '') {
            throw new PasswordRefusedException(PasswordRefusal::TooShort, 'A password is never empty (RFC 8265 §4.1).');
        }
        if (strlen($password) > PlainPassword::MAXIMUM_BYTES) {
            throw new PasswordRefusedException(PasswordRefusal::TooLong, sprintf('A password is at most %d bytes long.', PlainPassword::MAXIMUM_BYTES));
        }
    }
}
