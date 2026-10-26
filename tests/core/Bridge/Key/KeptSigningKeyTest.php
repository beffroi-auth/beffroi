<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeptSigning;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3, decisions 0018 and 0020: a key the tenant keeps out of its JWK Set and signs with, the SAML key
 * of a tenant among them, is the active key of its algorithm, opened by the KMS once per process as the keys of the
 * set are.
 */
final class KeptSigningKeyTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private OpenedKeys $opened;

    private SealedKeyProvider $provider;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->opened = Keys::opened();
        $this->provider = new SealedKeyProvider($this->keys, $this->opened);
    }

    /**
     * What signs is the active key of the algorithm, its private half opened.
     */
    #[Test]
    public function theActiveKeyOfTheAlgorithmSigns(): void
    {
        // Given
        $key = $this->activeKey(new KeptSigning(), Keys::pair());

        // When
        $opened = $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning());

        // Then
        static::assertSame([$key, Keys::pair()->privateJwk], [$opened->key, $opened->privateJwk]);
    }

    /**
     * Decision 0018: the KMS is asked once per key and per process, never at every message signed.
     */
    #[Test]
    public function theKeyIsOpenedOncePerProcess(): void
    {
        // Given
        $this->activeKey(new KeptSigning(), Keys::pair());
        $first = $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning());

        // When
        $second = $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning());

        // Then
        static::assertSame($first, $second);
    }

    /**
     * A tenant that holds no active key of the algorithm signs nothing with it.
     */
    #[Test]
    public function noActiveKeySignsNothing(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" has no active KEPT-SIGNING key to sign with.');

        // When
        $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning());
    }

    /**
     * RFC 7517 §4.2: the use is asserted and not deduced from the caller, a key of another use never signs.
     */
    #[Test]
    public function aKeyOfAnotherUseSignsNothing(): void
    {
        // Given
        $this->activeKey(new KeptSigning(KeyUse::Encryption), Keys::pair());

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('it is not a key that signs');

        // When
        $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning(KeyUse::Encryption));
    }

    /**
     * A rotation seen by a worker: the key it signed with before leaves the process.
     */
    #[Test]
    public function theKeyARotationReplacedLeavesTheProcess(): void
    {
        // Given
        $previous = $this->activeKey(new KeptSigning(), Keys::pair());
        $opened = $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning());
        $previous->startRetiring(Fixtures::now(), Fixtures::now());
        $this->keys->save($previous);
        $this->activeKey(new KeptSigning(), Keys::otherPair());

        // When
        $this->provider->activeKeptSigningKey($this->tenant, new KeptSigning());

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $previous));
    }

    /**
     * The material of a pair of the suite under the algorithm a test names, its public JWK saying so.
     */
    private function activeKey(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            [
                ...$pair->publicJwk,
                'alg' => $algorithm->name(),
                'use' => $algorithm->keyUse()->value,
            ],
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
