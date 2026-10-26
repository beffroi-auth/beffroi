<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-45, S-53: the values of an attribute of an accepted assertion, read by its name compared exactly.
 */
final class VerifiedAssertionTest extends TestCase
{
    #[Test]
    public function theValuesOfAnAttributeAreReadByItsName(): void
    {
        // When / Then
        static::assertSame(['member', 'staff'], self::verified()->values('eduPersonAffiliation'));
    }

    #[Test]
    public function anAttributeTheAssertionDoesNotCarryHasNoValue(): void
    {
        // When / Then
        static::assertSame([], self::verified()->values('EduPersonAffiliation'));
    }

    private static function verified(): VerifiedAssertion
    {
        return new VerifiedAssertion(
            'a7f3c2e1-persistent-alice',
            true,
            ['eduPersonAffiliation' => ['member', 'staff']],
            new DateTimeImmutable('2026-10-23T09:00:00+00:00'),
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            false,
        );
    }
}
