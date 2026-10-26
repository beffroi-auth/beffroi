<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\MappedClaimsWarmer;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Spec/saml.md S-16, section 6.2 step 1: the claim of each mapping of the declarations the compilation built, checked
 * against the claims the provider serves right after the compilation, in the same build; S-45, section 6.10 step 1:
 * the claim each attribute of the profile of an upstream identity provider fills, checked against the claims the
 * profile holds.
 */
final class MappedClaimsWarmerTest extends TestCase
{
    private const string ENTITY_ID = 'https://sp.example.com/saml';

    private const string CACHE_DIRECTORY = '/var/cache/prod';

    /**
     * S-16, section 6.2 step 1: a mapping of a claim the provider does not serve fails the build, naming the key of the
     * configuration, the service provider, the attribute and the claim.
     */
    #[Test]
    public function aMappingOfAClaimTheProviderDoesNotServeFailsTheBuild(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer(self::mapping('a_claim_no_provider_serves'), self::served(['sub', 'email']), self::profile([]));

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.service_providers": The service provider "https://sp.example.com/saml": '
        . 'the attribute "urn:oid:0.9.2342.19200300.100.1.3" maps the claim "a_claim_no_provider_serves", which this '
        . 'provider does not serve (spec/saml.md S-16).');

        // When
        $warmer->warmUp(self::CACHE_DIRECTORY);
    }

    /**
     * S-16, section 6.2 step 1: a mapping of a claim the provider serves builds, and the warmer leaves nothing to
     * preload.
     */
    #[Test]
    public function aMappingOfAClaimTheProviderServesBuilds(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer(self::mapping('email'), self::served(['sub', 'email']), self::profile([]));

        // When / Then
        static::assertSame([], $warmer->warmUp(self::CACHE_DIRECTORY));
    }

    /**
     * Section 6.2 step 1: the warmer is not optional, the warmers a kernel runs right after it compiled its container
     * being those that are not.
     */
    #[Test]
    public function itIsNotOptional(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer([], self::served([]), self::profile([]));

        // When / Then
        static::assertFalse($warmer->isOptional());
    }

    /**
     * Section 6.2 step 1: a deployment that declares no service provider asks nothing of its claims providers.
     */
    #[Test]
    public function noDeclarationAsksNothingOfTheClaims(): void
    {
        // Given
        $claims = $this->createMock(ServedClaimsInterface::class);
        $claims->expects(static::never())->method('names');
        $warmer = new MappedClaimsWarmer([], $claims, self::profile([]));

        // When
        $preloaded = $warmer->warmUp(self::CACHE_DIRECTORY);

        // Then
        static::assertSame([], $preloaded);
    }

    /**
     * S-45, section 6.10 step 1: an attribute of an upstream identity provider filling a claim the profile of a
     * person does not hold fails the build, naming the key of the configuration, the identity provider, the attribute
     * and the claim.
     */
    #[Test]
    public function anAttributeFillingAClaimTheProfileDoesNotHoldFailsTheBuild(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer([], self::served([]), self::profile(['given_name']), self::filling('email'));

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "https://idp.example.com/saml": '
        . 'the attribute "givenName" fills the claim "email", which the profile of a person does not hold in this deployment (spec/saml.md S-45).');

        // When
        $warmer->warmUp(self::CACHE_DIRECTORY);
    }

    /**
     * S-45, section 6.10 step 1: an attribute of an upstream identity provider filling a claim the profile holds
     * builds.
     */
    #[Test]
    public function anAttributeFillingAClaimTheProfileHoldsBuilds(): void
    {
        // Given
        $warmer = new MappedClaimsWarmer([], self::served([]), self::profile(['given_name']), self::filling('given_name'));

        // When / Then
        static::assertSame([], $warmer->warmUp(self::CACHE_DIRECTORY));
    }

    /**
     * Section 6.10 step 1: a deployment that declares no upstream identity provider asks nothing of the claims of the
     * profile.
     */
    #[Test]
    public function noUpstreamDeclarationAsksNothingOfTheProfile(): void
    {
        // Given
        $profile = $this->createMock(ProfileClaimsInterface::class);
        $profile->expects(static::never())->method('names');
        $warmer = new MappedClaimsWarmer([], self::served([]), $profile);

        // When
        $preloaded = $warmer->warmUp(self::CACHE_DIRECTORY);

        // Then
        static::assertSame([], $preloaded);
    }

    /**
     * A declaration of an upstream identity provider whose one attribute fills that claim.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function filling(string $claim): array
    {
        return [
            'https://idp.example.com/saml' => [
                'metadata' => '/srv/saml/idp-metadata.xml',
                'domains' => ['example.com'],
                'email_attribute' => 'mail',
                'profile' => ['givenName' => $claim],
            ],
        ];
    }

    /**
     * @param list<string> $names
     */
    private static function profile(array $names): ProfileClaimsInterface
    {
        $claims = static::createStub(ProfileClaimsInterface::class);
        $claims->method('names')->willReturn($names);

        return $claims;
    }

    /**
     * A declaration that maps one attribute from that claim.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function mapping(string $claim): array
    {
        return [
            self::ENTITY_ID => [
                'metadata' => '/srv/saml/sp-metadata.xml',
                'attributes' => [
                    'urn:oid:0.9.2342.19200300.100.1.3' => [
                        'claim' => $claim,
                    ],
                ],
            ],
        ];
    }

    /**
     * @param list<string> $names
     */
    private static function served(array $names): ServedClaimsInterface
    {
        $claims = static::createStub(ServedClaimsInterface::class);
        $claims->method('names')->willReturn($names);

        return $claims;
    }
}
