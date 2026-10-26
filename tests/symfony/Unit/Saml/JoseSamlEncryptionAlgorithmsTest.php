<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\JoseSamlEncryptionAlgorithms;
use Beffroi\Bundle\Saml\SamlEncryption;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * beffroi/saml, spec/saml.md S-64: the family of the keys the upstream identity providers encrypt for, one algorithm
 * per provider, named after it.
 */
final class JoseSamlEncryptionAlgorithmsTest extends TestCase
{
    /**
     * S-64: the algorithm of a provider is found by its name, "SAML-ENCRYPTION:" and the entity ID of the provider.
     */
    #[Test]
    public function theAlgorithmOfAProviderIsFoundByItsName(): void
    {
        // Given
        $algorithm = new SamlEncryption('https://idp-a.example/metadata');
        $registry = new JoseSamlEncryptionAlgorithms([new SamlEncryption('https://idp-b.example/metadata'), $algorithm]);

        // When / Then
        static::assertSame($algorithm, $registry->find('SAML-ENCRYPTION:https://idp-a.example/metadata'));
    }

    /**
     * S-64: the name of a provider nothing wires is refused, the refusal naming those that are.
     */
    #[Test]
    public function theNameOfAProviderNothingWiresIsRefused(): void
    {
        // Given
        $registry = new JoseSamlEncryptionAlgorithms([new SamlEncryption('https://idp-a.example/metadata')]);

        // When / Then
        static::assertSame(
            [
                null,
                'No SAML identity provider encrypts for a key named "SAML-ENCRYPTION:https://idp-c.example/metadata"; those that do encrypt for SAML-ENCRYPTION:https://idp-a.example/metadata.',
            ],
            [
                $registry->find('SAML-ENCRYPTION:https://idp-c.example/metadata'),
                $registry->refusalOf('SAML-ENCRYPTION:https://idp-c.example/metadata')->getMessage(),
            ],
        );
    }

    /**
     * S-64: a deployment that declares no provider wires none, and says so.
     */
    #[Test]
    public function aDeploymentThatDeclaresNoProviderWiresNone(): void
    {
        // Given
        $registry = new JoseSamlEncryptionAlgorithms([]);

        // When / Then
        static::assertSame(
            [[], 'No SAML identity provider encrypts for a key named "SAML-ENCRYPTION:https://idp-a.example/metadata"; none is declared.'],
            [$registry->all(), $registry->refusalOf('SAML-ENCRYPTION:https://idp-a.example/metadata')->getMessage()],
        );
    }

    /**
     * S-64: the key of a provider is an RSA pair, its public JWK carrying the name of the algorithm of that provider
     * and the use "enc".
     */
    #[Test]
    public function theKeyOfAProviderIsAnRsaKeyForEncryption(): void
    {
        // Given
        $algorithm = new SamlEncryption('https://idp-a.example/metadata', new RsaKeyBits(2048));

        // When
        $key = $algorithm->generateKey();

        // Then
        static::assertSame(
            ['RSA', 'SAML-ENCRYPTION:https://idp-a.example/metadata', 'enc', 'https://idp-a.example/metadata'],
            [$key->get('kty'), $key->get('alg'), $key->get('use'), $algorithm->identityProvider()],
        );
    }
}
