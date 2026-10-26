<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function base64_encode;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use DateTimeImmutable;
use function file_get_contents;

/**
 * The responses an upstream identity provider posts to the assertion consumer service of a tenant (spec/saml.md S-53),
 * written and signed by saml2-model's writer as an identity provider writes them: a persistent NameID unless the test
 * says another, a bearer confirmation of five minutes to the assertion consumer service, the audience of the service
 * provider, an authentication statement of the class PasswordProtectedTransport, and the attributes given, the
 * assertion signed by the key given.
 */
final class UpstreamResponses
{
    public const string PASSWORD_PROTECTED_TRANSPORT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    /**
     * The private key of the SimpleSAMLphp identity provider of the harnesses, whose certificate the document of the
     * judge publishes (IdentityProviderDocuments::simpleSamlPhp()).
     */
    public static function simpleSamlPhpKey(): PrivateKey
    {
        return PrivateKey::fromPem((string) file_get_contents(__DIR__ . '/../../saml2-bindings/Interop/simplesamlphp/installation/cert/idp.pem'));
    }

    /**
     * The fields of the form the browser posts, SAMLResponse and RelayState, the response written and signed.
     *
     * @param array<string, list<string>> $attributes the values of each attribute, by its name
     * @param array<string, list<string>> $repeated attributes written a second time after the others, as Keycloak names
     *                                              one attribute once per value
     *
     * @return array<string, string>
     */
    public static function form(
        PrivateKey $key,
        string $issuer,
        string $assertionConsumerService,
        string $audience,
        ?string $inResponseTo,
        DateTimeImmutable $now,
        array $attributes,
        ?string $relayState = null,
        ?DateTimeImmutable $authnInstant = null,
        NameId $nameId = new NameId('a7f3c2e1-persistent-alice', NameIdFormat::Persistent),
        string $contextClass = self::PASSWORD_PROTECTED_TRANSPORT,
        ?string $assertionId = null,
        ?Encryption $encryption = null,
        array $repeated = [],
        ?DateTimeImmutable $sessionNotOnOrAfter = null,
        ?string $certificatePem = null,
    ): array {
        $fields = [
            'SAMLResponse' => base64_encode(self::document(
                $key,
                $issuer,
                $assertionConsumerService,
                $audience,
                $inResponseTo,
                $now,
                $attributes,
                $authnInstant,
                $nameId,
                $contextClass,
                $assertionId,
                $encryption,
                $repeated,
                $sessionNotOnOrAfter,
                $certificatePem,
            )),
        ];
        if ($relayState !== null) {
            $fields['RelayState'] = $relayState;
        }

        return $fields;
    }

    /**
     * The fields of the form of a response whose status is not Success, Responder with the second-level code given, the
     * person having cancelled or failed at the provider, signed by the key given (model.md M-13).
     *
     * @return array<string, string>
     */
    public static function failure(
        PrivateKey $key,
        string $issuer,
        string $assertionConsumerService,
        string $inResponseTo,
        DateTimeImmutable $now,
        SecondLevelStatusCode $secondLevel,
        ?string $relayState = null,
    ): array {
        $response = new Response(
            SamlId::generate(),
            $now,
            new Issuer($issuer),
            $assertionConsumerService,
            $inResponseTo,
            new Status(StatusCode::Responder, $secondLevel),
            null,
        );
        $fields = [
            'SAMLResponse' => base64_encode(new Serializer()->serialize(new ResponseWriter()->writeFailure($response, new Signing($key)))),
        ];
        if ($relayState !== null) {
            $fields['RelayState'] = $relayState;
        }

        return $fields;
    }

    /**
     * @param array<string, list<string>> $attributes
     * @param array<string, list<string>> $repeated
     * @param string|null $certificatePem the certificate of the key the signature carries in its KeyInfo, none when null
     */
    private static function document(
        PrivateKey $key,
        string $issuer,
        string $assertionConsumerService,
        string $audience,
        ?string $inResponseTo,
        DateTimeImmutable $now,
        array $attributes,
        ?DateTimeImmutable $authnInstant,
        NameId $nameId,
        string $contextClass,
        ?string $assertionId,
        ?Encryption $encryption,
        array $repeated,
        ?DateTimeImmutable $sessionNotOnOrAfter,
        ?string $certificatePem,
    ): string {
        $statement = [];
        foreach ([$attributes, $repeated] as $written) {
            foreach ($written as $name => $values) {
                $statement[] = new Attribute($name, AttributeNameFormat::Uri, null, $values);
            }
        }
        $assertion = new Assertion(
            $assertionId ?? SamlId::generate(),
            $now,
            new Issuer($issuer),
            $nameId,
            new SubjectConfirmation($assertionConsumerService, $now->modify('+5 minutes'), $inResponseTo, null),
            new Conditions($now, $now->modify('+5 minutes'), [[$audience]], false),
            new AuthnStatement($authnInstant ?? $now, '_session-at-the-provider', $sessionNotOnOrAfter, $contextClass),
            $statement,
        );
        $response = new Response(
            SamlId::generate(),
            $now,
            new Issuer($issuer),
            $assertionConsumerService,
            $inResponseTo,
            new Status(StatusCode::Success),
            $assertion,
        );

        return new Serializer()->serialize(new ResponseWriter()->write(
            $response,
            new Signing($key, SignatureAlgorithm::RsaSha256, $certificatePem),
            encryption: $encryption,
        ));
    }
}
