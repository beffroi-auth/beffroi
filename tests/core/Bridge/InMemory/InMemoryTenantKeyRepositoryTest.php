<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeptEncryption;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

final class InMemoryTenantKeyRepositoryTest extends TestCase
{
    private Tenant $acme;

    private Tenant $other;

    private InMemoryTenantKeyRepository $repository;

    private TenantKey $otherKey;

    protected function setUp(): void
    {
        $this->acme = Fixtures::tenant();
        $this->other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository = new InMemoryTenantKeyRepository();
        $this->otherKey = self::activeKey($this->other, Keys::pair()->kid);
        $this->repository->save($this->otherKey);
    }

    #[Test]
    public function aTenantWithoutKeysHasNoActiveKey(): void
    {
        // When / Then
        static::assertNull($this->repository->findActive($this->acme, Algorithms::rs256()));
    }

    #[Test]
    public function aTenantWithoutKeysPublishesNothing(): void
    {
        // When / Then
        static::assertSame([], $this->repository->findInService($this->acme));
    }

    #[Test]
    public function keysAreScopedByTenantEvenWithTheSameKid(): void
    {
        // Given
        $acmeKey = self::activeKey($this->acme, Keys::pair()->kid);
        $this->repository->save($acmeKey);

        // When / Then
        static::assertSame($acmeKey, $this->repository->find($this->acme, Keys::pair()->kid));
        static::assertSame($this->otherKey, $this->repository->find($this->other, Keys::pair()->kid));
    }

    #[Test]
    public function anActiveKeyIsFoundActiveAndPublished(): void
    {
        // Given
        $acmeKey = self::activeKey($this->acme, Keys::pair()->kid);
        $this->repository->save($acmeKey);

        // When / Then
        static::assertSame($acmeKey, $this->repository->findActive($this->acme, Algorithms::rs256()));
        static::assertSame([$acmeKey], $this->repository->findInService($this->acme));
    }

    #[Test]
    public function anUnknownKidIsNotFound(): void
    {
        // When / Then
        static::assertNull($this->repository->find($this->acme, 'unknown'));
    }

    #[Test]
    public function aRetiringKeyIsPublishedButNotActive(): void
    {
        // Given
        $key = self::activeKey($this->acme, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $this->repository->save($key);

        // When / Then
        static::assertNull($this->repository->findActive($this->acme, Algorithms::rs256()));
        static::assertSame([$key], $this->repository->findInService($this->acme));
    }

    #[Test]
    public function aStagedKeyIsPublishedButNotActive(): void
    {
        // Given
        $key = new TenantKey(Keys::pair()->kid, $this->acme, Algorithms::rs256(), Keys::pair()->publicJwk, 'sealed', Fixtures::now(), Fixtures::now());
        $this->repository->save($key);

        // When / Then
        static::assertNull($this->repository->findActive($this->acme, Algorithms::rs256()));
        static::assertSame([$key], $this->repository->findInService($this->acme));
    }

    #[Test]
    public function aRetiredKeyIsFoundButNotPublished(): void
    {
        // Given
        $key = self::activeKey($this->acme, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->repository->save($key);

        // When / Then
        static::assertSame($key, $this->repository->find($this->acme, Keys::pair()->kid));
        static::assertSame([], $this->repository->findInService($this->acme));
    }

    /**
     * TenantKeyRepositoryInterface::findInService(): in creation order, whatever the order of the writes.
     */
    #[Test]
    public function thePublishedKeysComeInCreationOrder(): void
    {
        // Given
        $newest = self::activeKey($this->acme, Keys::pair()->kid, Fixtures::now());
        $oldest = new TenantKey(
            Keys::otherPair()->kid,
            $this->acme,
            Algorithms::rs256(),
            Keys::otherPair()->publicJwk,
            'sealed',
            Fixtures::now()->modify('-1 day'),
            Fixtures::now()->modify('-1 day'),
        );
        $this->repository->save($newest);
        $this->repository->save($oldest);

        // When / Then
        static::assertSame([$oldest, $newest], $this->repository->findInService($this->acme));
    }

    /**
     * Beffroi/saml S-64: one material is the key of one algorithm, so the key of another algorithm under a "kid" the
     * store holds is refused rather than written over it.
     */
    #[Test]
    public function theKeyOfAnotherAlgorithmUnderAKidHeldAlreadyIsRefused(): void
    {
        // Given
        $this->repository->save(self::activeKey($this->acme, Keys::pair()->kid));
        $other = new TenantKey(
            Keys::pair()->kid,
            $this->acme,
            new KeptEncryption(),
            [
                ...Keys::pair()->publicJwk,
                'alg' => new KeptEncryption()->name(),
                'use' => 'enc',
            ],
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The key "%s" of tenant "acme" is held already, and not as a key of KEPT-ENCRYPTION:a: one material is the key of one algorithm.',
            Keys::pair()->kid,
        ));

        // When
        $this->repository->save($other);
    }

    private static function activeKey(Tenant $tenant, string $kid, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        $key = new TenantKey(
            $kid,
            $tenant,
            Algorithms::rs256(),
            [
                'kid' => $kid,
            ] + Keys::pair()->publicJwk,
            'sealed',
            $createdAt ?? Fixtures::now(),
            $createdAt ?? Fixtures::now(),
        );
        $key->activate($createdAt ?? Fixtures::now());

        return $key;
    }
}
