<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use App\Tenant\TenantFactory;
use Beffroi\Core\Tests\Fixture\AttestationPolicies;
use Beffroi\Core\Tests\Fixture\Predicates;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Architecture §5.3
 */
final class TenantProviderTest extends DatabaseTestCase
{
    #[Test]
    public function theTenantIsTheRowOfTheConfiguration(): void
    {
        // When
        $tenant = self::tenant();

        // Then
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('default')));
        static::assertSame('https://op.test', (string) $tenant->issuer);
        static::assertSame('op.test', $tenant->name);
        static::assertTrue(self::entityManager()->contains($tenant));
        static::assertSame($tenant, self::entityManager()->find(Tenant::class, $tenant->id));
    }

    #[Test]
    public function theInstanceIsTheSameWithinAUnitOfWork(): void
    {
        // Given
        $provider = self::service('test.beffroi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();

        // When
        $again = $provider->provide();

        // Then
        static::assertSame($first, $again);
    }

    #[Test]
    public function theInstanceIsForgottenWhenTheEntityManagerIsCleared(): void
    {
        // Given
        $provider = self::service('test.beffroi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();
        self::entityManager()->clear();

        // When
        $second = $provider->provide();

        // Then
        static::assertNotSame($first, $second);
        static::assertFalse(self::entityManager()->contains($first));
        static::assertTrue(self::entityManager()->contains($second));
    }

    #[Test]
    public function theInstanceIsForgottenWhenTheServicesAreReset(): void
    {
        // Given
        $provider = self::service('test.beffroi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();
        self::service('services_resetter', ResetInterface::class)->reset();

        // When
        $second = $provider->provide();

        // Then
        static::assertNotSame($first, $second);
        static::assertTrue(self::entityManager()->contains($second));
        static::assertTrue($second->id->equals($first->id));
    }

    #[Test]
    public function synchronisingAgainWritesNothing(): void
    {
        // Given
        $synchronizer = self::service('test.beffroi.tenant_synchronizer', TenantSynchronizer::class);
        $first = $synchronizer->synchronize();

        // When
        $again = $synchronizer->synchronize();

        // Then
        static::assertSame($first, $again);
        static::assertSame($first, self::tenant());
    }

    #[Test]
    public function aMissingRowRefusesToServe(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null), self::managers());
        self::entityManager()->createQuery('DELETE FROM Beffroi\Core\Domain\Tenant\Tenant t')->execute();

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/has no row yet/');

        // When
        $provider->provide();
    }

    #[Test]
    public function aRowThatDisagreesWithTheConfigurationRefusesToServe(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://other.test', 'default', null), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/stored with the issuer "https:\/\/op.test" and configured with "https:\/\/other.test"/');

        // When
        $provider->provide();
    }

    #[Test]
    public function aRenamedTenantRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', 'Renamed'), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the name "op.test" and configured with "Renamed"');

        // When
        $provider->provide();
    }

    #[Test]
    public function synchronisingARenamedTenantWritesTheNewName(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', 'Renamed');
        $provider = new TenantProvider($factory, self::managers());

        // When
        $synchronized = new TenantSynchronizer($factory, self::managers(), self::derivations())->synchronize();
        self::reload();

        // Then
        static::assertSame('Renamed', $synchronized->name);
        static::assertSame('Renamed', $provider->provide()->name);
    }

    #[Test]
    public function theSynchroniserRefusesToMoveTheIssuer(): void
    {
        // Given
        $synchronizer = new TenantSynchronizer(self::factory('https://moved.test', 'default', null), self::managers(), self::derivations());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/the issuer of a tenant does not change/');

        // When
        $synchronizer->synchronize();
    }

    #[Test]
    public function anotherSlugIsAnotherTenant(): void
    {
        // When
        $other = new TenantSynchronizer(self::factory('https://other.test', 'other', null), self::managers(), self::derivations())->synchronize();
        self::reload();

        // Then
        static::assertTrue($other->id->equals(TenantFactory::identifier('other')));
        $stored = self::entityManager()->find(Tenant::class, $other->id) ?? static::fail('The other tenant was not stored.');
        static::assertTrue(new Issuer('https://other.test')->equals($stored->issuer));
        static::assertSame('https://op.test', (string) self::tenant()->issuer);
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aTenantWithAnotherPolicyRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null, self::OKTA_CLASSES), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the authentication_classes "phrh phr 2 1" and configured with "urn:okta:loa:2fa:any urn:okta:loa:1fa:any"');

        // When
        $provider->provide();
    }

    #[Test]
    public function synchronisingATenantWithAnotherPolicyWritesIt(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', null, self::OKTA_CLASSES);
        $provider = new TenantProvider($factory, self::managers());

        // When
        $synchronized = new TenantSynchronizer($factory, self::managers(), self::derivations())->synchronize();
        self::reload();

        // Then
        static::assertSame(['urn:okta:loa:2fa:any', 'urn:okta:loa:1fa:any'], $synchronized->authenticationContextPolicy->names());
        $stored = $provider->provide()->authenticationContextPolicy;
        static::assertSame(['urn:okta:loa:2fa:any', 'urn:okta:loa:1fa:any'], $stored->names());
        static::assertSame(TwoFactors::NAME, $stored->classes[0]->predicate->name());
    }

    /**
     * Decision 0046
     */
    #[Test]
    public function aTenantWithAnotherPasskeyAttestationRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null, passkeyAttestation: self::DIRECT), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the passkey_attestation "none, 0 root(s), 0 own root(s), 0 model(s) under alert" and configured with "direct, 0 root(s), 0 own root(s), 1 model(s) under alert"');

        // When
        $provider->provide();
    }

    /**
     * Decision 0046
     */
    #[Test]
    public function synchronisingATenantWithAnotherPasskeyAttestationWritesIt(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', null, passkeyAttestation: self::DIRECT);

        // When
        new TenantSynchronizer($factory, self::managers(), self::derivations())->synchronize();
        self::reload();

        // Then
        $stored = new TenantProvider($factory, self::managers())->provide()->passkeyAttestation;
        static::assertSame('direct', $stored->policy->name());
        static::assertSame('2027-03-31', $stored->modelsUnderAlert[0]->day());
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aTenantThatConfiguresNothingSpeaksTheDefaultPolicy(): void
    {
        // When
        $tenant = new TenantProvider(self::factory('https://op.test', 'default', null), self::managers())->provide();

        // Then
        static::assertTrue(AuthenticationContextPolicy::default()->equals($tenant->authenticationContextPolicy));
    }

    #[Test]
    public function aTenantWithAnotherLookRefusesToServeUntilSynchronised(): void
    {
        // Given
        $provider = new TenantProvider(self::factory('https://op.test', 'default', null, look: self::LOOK), self::managers());

        // Then
        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageIsOrContains('stored with the look "none" and configured with "logo https://acme.example/logo.svg, #1b4b8f on #ffffff"');

        // When
        $provider->provide();
    }

    #[Test]
    public function synchronisingATenantWithAnotherLookWritesIt(): void
    {
        // Given
        $factory = self::factory('https://op.test', 'default', null, look: self::LOOK);
        $provider = new TenantProvider($factory, self::managers());

        // When
        $synchronized = new TenantSynchronizer($factory, self::managers(), self::derivations())->synchronize();
        self::reload();

        // Then
        static::assertSame('https://acme.example/logo.svg', $synchronized->look->logoUri?->value);
        $stored = $provider->provide()->look;
        static::assertSame('https://acme.example/logo.svg', $stored->logoUri?->value);
        static::assertSame('#1b4b8f', $stored->primaryColor);
        static::assertSame('#ffffff', $stored->primaryContentColor);
    }

    #[Test]
    public function aTenantThatDeclaresNoLookHasNone(): void
    {
        // When
        $tenant = new TenantProvider(self::factory('https://op.test', 'default', null), self::managers())->provide();

        // Then
        static::assertFalse($tenant->look->isDeclared());
    }

    private const array DIRECT = [
        'policy' => 'direct',
        'models_under_alert' => [
            'cb69481e-8ff7-4039-93ec-0a2729a154a8' => '2027-03-31',
        ],
    ];

    private const array LOOK = [
        'logo_uri' => 'https://acme.example/logo.svg',
        'primary_color' => '#1b4b8f',
        'primary_content_color' => '#ffffff',
    ];

    private const array OKTA_CLASSES = [
        'urn:okta:loa:2fa:any' => 'two_factors',
        'urn:okta:loa:1fa:any' => 'single_factor',
    ];

    /**
     * @param array<array-key, string> $authenticationClasses
     * @param array<array-key, mixed> $look
     */
    private const array SELF_SERVED_CLAIMS = ['nickname', 'zoneinfo', 'locale', 'birthdate'];

    /**
     * @param array<array-key, string> $authenticationClasses
     * @param array<array-key, mixed> $look
     * @param array<array-key, mixed> $selfServedClaims
     * @param array<array-key, mixed> $passkeyAttestation
     */
    private static function factory(
        string $issuer,
        string $slug,
        ?string $name,
        array $authenticationClasses = [],
        array $look = [],
        array $selfServedClaims = self::SELF_SERVED_CLAIMS,
        array $passkeyAttestation = [],
    ): TenantFactory {
        return new TenantFactory(
            $issuer,
            $slug,
            $name,
            new MockClock(self::now()),
            Predicates::wired(),
            $authenticationClasses,
            $look,
            $selfServedClaims,
            passkeyAttestations: AttestationPolicies::wired(),
            passkeyAttestation: $passkeyAttestation,
        );
    }
}
