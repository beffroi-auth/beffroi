<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryHeldKeyJwsVerifier;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7515 §4.1.4, decision 0060
 */
final class HeldKeyJwsVerificationTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
    }

    #[Test]
    public function aSignatureUnderAKeyRetiredSinceVerifies(): void
    {
        // Given
        $key = $this->held(Algorithms::rs256(), Keys::pair());
        $signed = $this->signed();
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());

        // When
        $verified = new JwtLibraryHeldKeyJwsVerifier($this->keys, Algorithms::all())->verify($this->tenant, $signed);

        // Then
        static::assertSame('the head', $verified->payload);
    }

    #[Test]
    public function aSignatureUnderAKeyTheTenantNeverHeldIsRefused(): void
    {
        // Given
        $this->held(Algorithms::rs256(), Keys::pair());
        $signed = $this->signed();
        $this->keys = new InMemoryTenantKeyRepository();

        // Then
        $this->expectException(InvalidJwsException::class);
        $this->expectExceptionMessageIs('The token names a key this tenant never signed with.');

        // When
        new JwtLibraryHeldKeyJwsVerifier($this->keys, Algorithms::all())->verify($this->tenant, $signed);
    }

    #[Test]
    public function aSignatureNamingAKeyOfEncryptionIsRefused(): void
    {
        // Given
        $this->held(Algorithms::rs256(), Keys::pair());
        $signed = $this->signed();
        $this->keys = new InMemoryTenantKeyRepository();
        $encryption = Keys::encryptionPair();
        $this->held(Algorithms::ecdhEsA256Kw(), new GeneratedKeyPair(
            Keys::pair()->kid,
            Algorithms::ecdhEsA256Kw(),
            $encryption->privateJwk,
            [...$encryption->publicJwk, 'kid' => Keys::pair()->kid],
        ));

        // Then
        $this->expectException(InvalidJwsException::class);
        $this->expectExceptionMessageIs('The token names a key this tenant never signed with.');

        // When
        new JwtLibraryHeldKeyJwsVerifier($this->keys, Algorithms::all())->verify($this->tenant, $signed);
    }

    private function signed(): string
    {
        return new JwtLibraryJwsSigner(new SealedKeyProvider($this->keys, Keys::opened()), Algorithms::all())->sign(
            $this->tenant,
            Algorithms::rs256(),
            'the head',
        );
    }

    private function held(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
