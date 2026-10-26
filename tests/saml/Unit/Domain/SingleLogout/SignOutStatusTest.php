<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleLogout;

use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-24, SAML Core §3.2.2.2: the status codes of the answer to a logout request.
 */
final class SignOutStatusTest extends TestCase
{
    /**
     * Core §3.2.2.2, spec/saml.md S-34: Success is a top-level code alone; a partial logout is Success above
     * PartialLogout; a refusal is Requester above its second-level code.
     */
    #[Test]
    #[DataProvider('provideCodes')]
    public function itNamesItsCodes(SignOutStatus $status, string $topLevel, ?string $secondLevel): void
    {
        // When / Then
        static::assertSame([$topLevel, $secondLevel], [$status->topLevel(), $status->secondLevel()]);
    }

    /**
     * @return iterable<string, array{SignOutStatus, string, ?string}>
     */
    public static function provideCodes(): iterable
    {
        yield 'every session named ended' => [SignOutStatus::Success, 'urn:oasis:names:tc:SAML:2.0:status:Success', null];
        yield 'a service provider of the sessions not told' => [
            SignOutStatus::PartialLogout,
            'urn:oasis:names:tc:SAML:2.0:status:Success',
            'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
        ];
        yield 'a session of another principal' => [
            SignOutStatus::UnknownPrincipal,
            'urn:oasis:names:tc:SAML:2.0:status:Requester',
            'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
        ];
        yield 'no session named' => [
            SignOutStatus::RequestUnsupported,
            'urn:oasis:names:tc:SAML:2.0:status:Requester',
            'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
        ];
    }
}
