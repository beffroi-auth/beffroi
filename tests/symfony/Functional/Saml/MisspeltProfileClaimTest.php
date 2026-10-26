<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Filesystem\Filesystem;

/**
 * beffroi/saml, spec/saml.md S-45, section 6.10 step 1: a deployment whose configuration has an attribute of an upstream
 * identity provider fill a claim the profile of a person does not hold, a misspelt one (config_test_misspelt_claim.yml),
 * fails the build of its container, and not the first sign-in through that provider, which would fill nothing.
 */
final class MisspeltProfileClaimTest extends KernelTestCase
{
    /**
     * The environment whose configuration names that claim.
     */
    private const string MISSPELT_CLAIM = 'test_misspelt_claim';

    /**
     * S-45, section 6.10 step 1: the boot that compiles the container fails, the warmer that runs right after the
     * compilation refusing the claim, against the claims the deployment wires for the profile, with the failure of
     * the configuration, which names the identity provider, the attribute and the claim.
     */
    #[Test]
    public function theBootThatCompilesTheContainerFails(): void
    {
        // Given
        $kernel = self::createKernel([
            'environment' => self::MISSPELT_CLAIM,
        ]);
        // a container a previous run wrote is read back without the warmer: this boot compiles its own
        new Filesystem()->remove($kernel->getBuildDir());

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Invalid configuration for path "beffroi.saml.identity_providers": The identity provider "https://idp.example.org/saml": '
        . 'the attribute "givenName" fills the claim "givenName", which the profile of a person does not hold in this deployment (spec/saml.md S-45).');

        // When
        $kernel->boot();
    }
}
