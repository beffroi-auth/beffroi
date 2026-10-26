<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Xml\Enc\PrivateDecryptionKey;

/**
 * The response fixtures of tests/saml2-model/Fixture/ (tests/saml2-model/Support/ResponseFixtureBuilder.php) and the identity provider they
 * come from, https://idp.example.com/saml, whose metadata lists the identity provider's test key; the response answers
 * _request at https://sp.example.com/saml/acs for https://sp.example.com/saml, a second before the frozen clock of
 * AssertionFixtures.
 */
trait ResponseFixtures
{
    use AssertionFixtures;

    /**
     * The metadata of an identity provider, its signing key the test key $key (M-3): the identity provider's by
     * default, the service provider's for a key the identity provider never signed with.
     *
     * @param 'idp'|'sp'|'idp-b' $key
     */
    private static function identityProvider(
        string $entityId = 'https://idp.example.com/saml',
        string $key = 'idp',
    ): IdentityProvider {
        return new IdentityProvider(
            $entityId,
            [MetadataFixtures::certificate($key)],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
        );
    }

    /**
     * The private key of the test key $key, the service provider's by default, for which the responses of
     * tests/saml2-model/Fixture/encrypted/ are encrypted (section 6.7); the identity provider's is another key, and
     * sp-b the one the service provider gives with the second identity provider (section 5.5).
     *
     * @param 'idp'|'sp'|'sp-b' $key
     */
    private static function decryptionKey(string $key = 'sp'): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(MetadataFixtures::bytes(match ($key) {
            'idp' => 'keys/idp-signing-key.pem',
            'sp' => 'keys/sp-signing-key.pem',
            'sp-b' => 'keys/sp-b-encryption-key.pem',
        }));
    }

    /**
     * The response of $fixture as the consumer receives it (section 5.4).
     */
    private function unverified(string $fixture): UnverifiedResponse
    {
        return UnverifiedResponse::of($this->document($fixture));
    }
}
