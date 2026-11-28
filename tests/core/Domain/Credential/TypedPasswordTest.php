<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Credential\TypedPassword;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class TypedPasswordTest extends TestCase
{
    /**
     * RFC 8265 §4.2.3, §8.2
     */
    #[Test]
    public function aPasswordTypedInItsEnforcedFormHasThatFormAlone(): void
    {
        // When / Then
        static::assertSame(['correct horse battery staple'], TypedPassword::of('correct horse battery staple')?->forms());
    }

    /**
     * RFC 8265 §4.2.3, §6.2
     */
    #[Test]
    public function aPasswordTypedInAnotherFormHasItsEnforcedFormThenItsBytes(): void
    {
        // When / Then
        static::assertSame(['foo bar', "foo\u{1680}bar"], TypedPassword::of("foo\u{1680}bar")?->forms());
    }

    /**
     * RFC 8265 §4.1, §4.3
     */
    #[Test]
    #[DataProvider('provideWhatIsNoPassword')]
    public function whatTheProfileRefusesIsNoTypedPassword(string $typed): void
    {
        // When / Then
        static::assertNull(TypedPassword::of($typed));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoPassword(): iterable
    {
        yield 'nothing, example 17 of RFC 8265 §4.3' => [''];
        yield 'a tabulation, example 18' => ["my cat is a \u{0009}by"];
        yield 'more bytes than a hasher takes' => [str_repeat('a', PlainPassword::MAXIMUM_BYTES + 1)];
    }

    /**
     * RFC 8265 §4.2.3
     */
    #[Test]
    public function theEnforcedFormIsVerifiedFirst(): void
    {
        // Given
        $tried = [];

        // When
        TypedPassword::of("foo\u{1680}bar")?->verifiedBy(static function (string $form) use (&$tried): bool {
            $tried[] = $form;

            return true;
        });

        // Then
        static::assertSame(['foo bar'], $tried);
    }

    /**
     * RFC 8265 §6.2, decision 0058
     */
    #[Test]
    public function everyFormIsVerifiedBeforeNoneIsFound(): void
    {
        // Given
        $tried = [];

        // When
        TypedPassword::of("foo\u{1680}bar")?->verifiedBy(static function (string $form) use (&$tried): bool {
            $tried[] = $form;

            return false;
        });

        // Then
        static::assertSame(['foo bar', "foo\u{1680}bar"], $tried);
    }

    /**
     * RFC 8265 §6.2
     */
    #[Test]
    public function theFormThatVerifiedIsNamed(): void
    {
        // When / Then
        static::assertSame(
            "foo\u{1680}bar",
            TypedPassword::of("foo\u{1680}bar")?->verifiedBy(static fn (string $form): bool => $form === "foo\u{1680}bar"),
        );
    }
}
