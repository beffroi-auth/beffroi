<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Filesystem\Filesystem;

/**
 * beffroi/saml, spec/saml.md S-16, section 6.2 step 1: a deployment whose configuration maps an attribute from a claim
 * the provider does not serve (config_test_unserved_claim.yml) fails the build of its container, and not its first
 * refresh or its first login.
 */
final class UnservedClaimTest extends KernelTestCase
{
    /**
     * The environment whose configuration maps that claim.
     */
    private const string UNSERVED_CLAIM = 'test_unserved_claim';

    /**
     * S-16, section 6.2 step 1: the boot that compiles the container fails, the warmer that runs right after the
     * compilation refusing the mapping with the failure of the configuration, which names the service provider, the
     * attribute and the claim.
     */
    #[Test]
    public function theBootThatCompilesTheContainerFails(): void
    {
        // Given
        $kernel = self::createKernel([
            'environment' => self::UNSERVED_CLAIM,
        ]);
        // a container a previous run wrote is read back without the warmer: this boot compiles its own
        new Filesystem()->remove($kernel->getBuildDir());

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.service_providers": The service provider "https://sp.example.com/saml": '
        . 'the attribute "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" maps the claim "a_claim_no_provider_serves", which this '
        . 'provider does not serve (spec/saml.md S-16).');

        // When
        $kernel->boot();
    }
}
