<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Key\StagingDelay;
use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Saml\IdentityProviderSegment;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use function array_find;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * beffroi/saml, spec/saml.md sections 6.1 and 9: the metadata of the SAML identity provider of the tenant, served on
 * the protocol plane, its key drawn and rotated by the key commands as every key of the tenant.
 */
final class IdentityProviderMetadataTest extends ConsoleTestCase
{
    private const string METADATA = '/saml/metadata';

    /**
     * Section 6.1, S-4: the metadata served is read back by saml2-model's MetadataReader, its entity ID the URL of the
     * metadata under the issuer, both services at their URL on both bindings, WantAuthnRequestsSigned true as the
     * tenant left it, the certificate of its one key.
     */
    #[Test]
    public function theMetadataOfTheTenantIsReadBackByTheModel(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $descriptor = $this->servedDescriptor();
        $identityProvider = $descriptor->identityProvider;
        static::assertNotNull($identityProvider);
        static::assertSame(
            [
                'https://op.test/saml/metadata',
                true,
                1,
                [
                    [Binding::HttpRedirect, 'https://op.test/saml/sso'],
                    [Binding::HttpPost,     'https://op.test/saml/sso'],
                ],
                [
                    [Binding::HttpRedirect, 'https://op.test/saml/slo'],
                    [Binding::HttpPost,     'https://op.test/saml/slo'],
                ],
            ],
            [
                $descriptor->entityId,
                $identityProvider->wantAuthnRequestsSigned,
                \count($identityProvider->signingCertificates),
                array_map(static fn ($endpoint): array => [$endpoint->binding, $endpoint->location], $identityProvider->singleSignOnServices),
                array_map(static fn ($endpoint): array => [$endpoint->binding, $endpoint->location], $identityProvider->singleLogoutServices),
            ],
        );
    }

    /**
     * S-4, section 6.1 step 3: a request that names another host is served the metadata of the tenant, its entity ID
     * and its services under the issuer, never under the Host header of the request.
     */
    #[Test]
    public function theEndpointsAreUnderTheIssuerNotUnderTheRequestHost(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA, server: [
            'HTTP_HOST' => 'attacker.example',
        ]);

        // Then
        $descriptor = $this->servedDescriptor();
        static::assertSame(
            [
                'https://op.test/saml/metadata',
                ['https://op.test/saml/sso', 'https://op.test/saml/sso'],
                ['https://op.test/saml/slo', 'https://op.test/saml/slo'],
            ],
            [
                $descriptor->entityId,
                array_map(static fn ($endpoint): string => $endpoint->location, $descriptor->identityProvider->singleSignOnServices ?? []),
                array_map(static fn ($endpoint): string => $endpoint->location, $descriptor->identityProvider->singleLogoutServices ?? []),
            ],
        );
    }

    /**
     * Section 6.1 step 6: served as SAML metadata, cacheable for the max-age of the keys of the tenant, two minutes in
     * this kernel, so that a service provider that fetches it finds the next certificate within minutes of its staging.
     */
    #[Test]
    public function itIsServedAsSamlMetadataForTheMaxAgeOfTheKeys(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            ['application/samlmetadata+xml', true, '120'],
            [
                $response->headers->get('Content-Type'),
                $response->headers->hasCacheControlDirective('public'),
                $response->headers->getCacheControlDirective('max-age'),
            ],
        );
    }

    /**
     * S-3, section 6.1 step 2: the certificate served is around the public half of the SAML key the tenant holds.
     */
    #[Test]
    public function theCertificateIsAroundTheSamlKeyOfTheTenant(): void
    {
        // Given
        $key = self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($key)],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->identityProvider->signingCertificates ?? []),
        );
    }

    /**
     * S-1: the SAML key the tenant holds is not in its JWK Set.
     */
    #[Test]
    public function theJwkSetDoesNotCarryTheSamlKey(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame([], self::json($this->browser->getResponse())['keys'] ?? null);
    }

    /**
     * S-2: a rotation of the SAML key stages the next one, whose certificate is served beside the current one's before
     * the staged key signs anything.
     */
    #[Test]
    public function aRotationPublishesTheNextCertificateBeforeItSigns(): void
    {
        // Given
        $current = self::generate();
        // a key created later, so that the creation order of the two is the order they were drawn in
        self::aSecondLater();
        $rotation = self::console('beffroi:keys:rotate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $rotation->getStatusCode(), $rotation->getDisplay());
        $next = array_find(
            self::keys()->findInService(self::tenant()),
            static fn (TenantKey $key): bool => $key->isStaged(),
        ) ?? static::fail('The rotation staged no key.');

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(
            [KeyStatus::Staged, [CertificateModulus::ofKey($current), CertificateModulus::ofKey($next)]],
            [$next->status, array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->identityProvider->signingCertificates ?? [])],
        );
    }

    /**
     * S-12, issue #738: a key is staged for the staging delay of its family, seven days for the SAML key, while a key of
     * the JWK Set waits what it always waited, the max-age of the JWK Set plus the 60 s refetch cooldown of oidc_login:
     * 180 s on the 120 s max-age of this kernel, 360 s on the default one.
     */
    #[Test]
    #[DataProvider('provideFamilies')]
    public function aRotationStagesAKeyForTheStagingDelayOfItsFamily(string $algorithm, int $stagingDelay): void
    {
        // Given
        self::console('beffroi:keys:generate', [
            '--algorithm' => $algorithm,
        ]);
        self::aSecondLater();

        // When
        $staged = self::rotate($algorithm);

        // Then
        static::assertSame($stagingDelay, $staged->activationDueAt->getTimestamp() - $staged->createdAt->getTimestamp());
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideFamilies(): iterable
    {
        yield 'the SAML key, a family of its own' => [SamlSigning::NAME, SamlSigningAlgorithmInterface::STAGING_DELAY];
        yield 'a key of the JWK Set' => ['RS256', StagingDelay::seconds(null, 120)];
    }

    /**
     * S-2, S-12, the acceptance of issue #738: the next certificate is in the metadata for the whole staging delay of
     * the SAML key before that key signs anything, the scheduled step leaving it staged a second before its week
     * ends.
     */
    #[Test]
    public function theNextCertificateIsPublishedForTheWholeStagingDelayBeforeItSigns(): void
    {
        // Given
        $current = self::generate();
        self::aSecondLater();
        $next = self::rotate(SamlSigning::NAME);
        self::mockTime($next->activationDueAt->modify('-1 second'));
        self::tick();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(
            [KeyStatus::Staged, KeyStatus::Active, [CertificateModulus::ofKey($current), CertificateModulus::ofKey($next)]],
            [
                self::key($next->kid)->status,
                self::key($current->kid)->status,
                array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->identityProvider->signingCertificates ?? []),
            ],
        );
    }

    /**
     * S-12: once its week has passed, the scheduled step makes the staged SAML key the one that signs.
     */
    #[Test]
    public function theScheduledStepActivatesTheSamlKeyAtTheEndOfItsStagingDelay(): void
    {
        // Given
        $current = self::generate();
        self::aSecondLater();
        $next = self::rotate(SamlSigning::NAME);
        self::mockTime($next->activationDueAt);

        // When
        self::tick();

        // Then
        static::assertSame([KeyStatus::Active, KeyStatus::Retiring], [self::key($next->kid)->status, self::key($current->kid)->status]);
    }

    /**
     * S-12, the acceptance of issue #738: the metadata says how long a service provider may keep it, and that is
     * shorter than the window the next SAML key was staged with, so that a service provider that honours it fetches
     * the next certificate before that key signs.
     */
    #[Test]
    public function theCacheDurationOfTheMetadataIsShorterThanTheStagingDelayOfTheSamlKey(): void
    {
        // Given
        self::generate();
        self::aSecondLater();
        $next = self::rotate(SamlSigning::NAME);

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $cacheDuration = SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent()))->root()->getAttribute('cacheDuration');
        static::assertSame(1, preg_match('~^PT(\d+)S$~', $cacheDuration ?? '', $seconds), (string) $cacheDuration);
        static::assertLessThan($next->activationDueAt->getTimestamp() - $next->createdAt->getTimestamp(), (int) $seconds[1]);
    }

    /**
     * S-41: the service provider of the tenant left off, as this kernel leaves it, serves no metadata, though the
     * tenant holds a SAML key in service for its identity provider.
     */
    #[Test]
    public function theServiceProviderLeftOffServesNoMetadata(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-41, S-51: the service provider of the tenant left off, as this kernel leaves it, starts no sign-on at an
     * upstream identity provider, though the tenant holds a SAML key in service for its identity provider.
     */
    #[Test]
    public function theServiceProviderLeftOffStartsNoSignOn(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/saml/sp/sign-on', [
            'interaction' => 'an-interaction',
            'identity_provider' => 'https://idp.example.org/saml',
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-41, S-65: the service provider of the tenant left off gives no upstream identity provider its metadata.
     */
    #[Test]
    public function theServiceProviderLeftOffGivesNoProviderItsMetadata(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/saml/sp/metadata/' . IdentityProviderSegment::of('https://idp-a.example/metadata'));

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Section 6.1 step 1: a tenant that holds no SAML key has no metadata to serve.
     */
    #[Test]
    public function aTenantWithoutASamlKeyServesNoMetadata(): void
    {
        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The first SAML key of the tenant, drawn by the command an operator runs and active at once.
     */
    private static function generate(): TenantKey
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        return self::keys()->findInService(self::tenant())[0] ?? static::fail('The command drew no key.');
    }

    /**
     * A rotation as an operator asks for one, which stages the next key of the algorithm beside the active one.
     */
    private static function rotate(string $algorithm): TenantKey
    {
        $rotation = self::console('beffroi:keys:rotate', [
            '--algorithm' => $algorithm,
        ]);
        static::assertSame(Command::SUCCESS, $rotation->getStatusCode(), $rotation->getDisplay());

        return (
            array_find(
                self::keys()->findInService(self::tenant()),
                static fn (TenantKey $key): bool => $key->isStaged(),
            ) ?? static::fail('The rotation staged no key.')
        );
    }

    /**
     * What the worker does on a tick: the recurring message of the life of the keys, on the command bus.
     */
    private static function tick(): void
    {
        self::service('test.beffroi.command_bus', MessageBusInterface::class)->dispatch(new AdvanceKeyLifecycle());
    }

    private static function key(string $kid): TenantKey
    {
        return self::keys()->find(self::tenant(), $kid) ?? static::fail(sprintf('The key "%s" is not stored.', $kid));
    }

    private static function keys(): TenantKeyRepositoryInterface
    {
        return self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class);
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }
}
