<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Replay;

use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\Replay\RememberedMessage;
use function hash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-23: the key an assertion or a logout message is remembered under, the SHA-256 of its tenant, its issuer and its ID.
 */
final class RememberedMessageTest extends TestCase
{
    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * S-23: the three, each followed by a NUL, in hexadecimal.
     */
    #[Test]
    public function theKeyIsTheDigestOfTheTenantTheIssuerAndTheId(): void
    {
        // When / Then
        static::assertSame(
            hash('sha256', $this->tenant->id->toRfc4122() . "\0https://sp.example.org/saml\0_id\0"),
            RememberedMessage::keyOf($this->tenant, 'https://sp.example.org/saml', '_id'),
        );
    }

    /**
     * S-23, M-11: the same ID from two issuers is two messages.
     */
    #[Test]
    public function twoIssuersGiveTwoKeys(): void
    {
        // When / Then
        static::assertNotSame(
            RememberedMessage::keyOf($this->tenant, 'https://sp.example.org/saml', '_id'),
            RememberedMessage::keyOf($this->tenant, 'https://other.example.org/saml', '_id'),
        );
    }

    /**
     * S-23: the same message under two tenants is two rows, each under its tenant.
     */
    #[Test]
    public function twoTenantsGiveTwoKeys(): void
    {
        // When / Then
        static::assertNotSame(
            RememberedMessage::keyOf($this->tenant, 'https://sp.example.org/saml', '_id'),
            RememberedMessage::keyOf(Fixtures::tenant('globex', 'https://id.globex.example'), 'https://sp.example.org/saml', '_id'),
        );
    }

    /**
     * S-23, decision 0011: a row names no person, a digest, its tenant and when it may be forgotten.
     */
    #[Test]
    public function aRowNamesNoPerson(): void
    {
        // When / Then
        static::assertEquals(
            [
                'key' => new NoPersonalDatum(Reason::HASHED),
                'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
                'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            ],
            RememberedMessage::classifiedFields(),
        );
    }
}
