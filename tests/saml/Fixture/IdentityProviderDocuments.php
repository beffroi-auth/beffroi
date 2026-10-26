<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use DateTimeImmutable;
use function file_get_contents;
use function preg_replace;
use function sprintf;
use function str_replace;

/**
 * The metadata documents of an upstream identity provider the tests of spec/saml.md section 6.10 read: the one the
 * SimpleSAMLphp 2.5.3.1 identity provider of the judge publishes (issue #788), as it is or with one change a test
 * names, and a document the model's writer signs with a test key of saml2-model.
 */
final readonly class IdentityProviderDocuments
{
    /**
     * The entity ID of the SimpleSAMLphp identity provider of the judge, at the host the stack serves it on.
     */
    public const string SIMPLESAMLPHP = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

    /**
     * The entity ID of the document the model's writer signs.
     */
    public const string SIGNED = 'https://idp.example.org/saml';

    /**
     * The document SimpleSAMLphp 2.5.3.1 published on 30 September 2026 (tests/saml2-model/Fixture/real/), its URLs
     * moved from http://localhost:8081 to https://saml-idp.localhost, the host of the judge of issue #788, and nothing
     * else: the service provider refuses a single sign-on service in plain http (spec/saml.md S-43), and the recording
     * of saml2-model keeps the bytes as they were published. Its signing key and its encryption key are the test key
     * of the identity provider of the harnesses (tests/saml2-bindings/Interop/simplesamlphp/installation/cert/).
     */
    public static function path(): string
    {
        return __DIR__ . '/metadata/simplesamlphp-2.5.3.1-idp-metadata-https.xml';
    }

    /**
     * The document of the entity SIGNED as a file of the fixtures, its single sign-on service at SIGNED/sso on
     * HTTP-Redirect, the test key of an identity provider of saml2-model for signing: what signingOnAt() writes for
     * that service, kept so that a deployment of the tests declares it (config_test_service_provider.yml).
     */
    public static function signedPath(): string
    {
        return __DIR__ . '/metadata/signed-idp-metadata.xml';
    }

    public static function simpleSamlPhp(): string
    {
        return (string) file_get_contents(self::path());
    }

    /**
     * The SimpleSAMLphp document with a validUntil on its md:EntityDescriptor, which readTrusted() reads without a
     * signature to break.
     */
    public static function simpleSamlPhpValidUntil(string $validUntil): string
    {
        return str_replace(
            sprintf('entityID="%s"', self::SIMPLESAMLPHP),
            sprintf('entityID="%s" validUntil="%s"', self::SIMPLESAMLPHP, $validUntil),
            self::simpleSamlPhp(),
        );
    }

    /**
     * The SimpleSAMLphp document without its md:KeyDescriptor for signing, its key for encryption left.
     */
    public static function simpleSamlPhpWithoutSigningKey(): string
    {
        return (string) preg_replace('~\s*<md:KeyDescriptor use="signing">.*?</md:KeyDescriptor>~s', '', self::simpleSamlPhp());
    }

    /**
     * The SimpleSAMLphp document whose single sign-on service is at the location given.
     */
    public static function simpleSamlPhpSigningOnAt(string $location): string
    {
        return str_replace(
            'Location="https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService"',
            sprintf('Location="%s"', $location),
            self::simpleSamlPhp(),
        );
    }

    /**
     * The SimpleSAMLphp document whose single sign-on service is on HTTP-POST, at the same location, and on no other
     * binding.
     */
    public static function simpleSamlPhpSigningOnOverPost(): string
    {
        return str_replace(
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService"',
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService"',
            self::simpleSamlPhp(),
        );
    }

    /**
     * An unsigned identity provider document of the entity SIGNED, its single sign-on services those given, in their
     * order, the test key of an identity provider of saml2-model for signing.
     *
     * @param list<Endpoint> $singleSignOnServices
     */
    public static function signingOnAt(array $singleSignOnServices): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(self::SIGNED, null, identityProvider: new IdentityProvider(
                self::SIGNED,
                [MetadataFixtures::certificate('idp')],
                [],
                $singleSignOnServices,
            )),
            null,
        ));
    }

    /**
     * An identity provider document signed by a test key of saml2-model, its validUntil given: the entity SIGNED, its
     * single sign-on service at SIGNED/sso on HTTP-Redirect, the test key of an identity provider of saml2-model for
     * signing.
     *
     * @param 'idp'|'sp' $key the key that signs the document
     */
    public static function signed(?DateTimeImmutable $validUntil, string $key = 'idp'): string
    {
        return new Serializer()->serialize(new MetadataWriter()->write(
            new EntityDescriptor(self::SIGNED, $validUntil, identityProvider: new IdentityProvider(
                self::SIGNED,
                [MetadataFixtures::certificate('idp')],
                [],
                [new Endpoint(Binding::HttpRedirect, self::SIGNED . '/sso')],
            )),
            new Signing(MetadataFixtures::signingKey($key)),
        ));
    }

    /**
     * The certificate of a test key of saml2-model, as a declaration pins it.
     *
     * @param 'idp'|'sp' $key
     */
    public static function signer(string $key = 'idp'): Certificate
    {
        return new Certificate(MetadataFixtures::certificate($key));
    }
}
