<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use function array_map;
use function base64_decode;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Bridge\Model\ModelSignOnResponder;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Domain\SingleSignOn\SignOnStatus;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignatureCertificates;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat as ModelAttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Closure;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function preg_replace_callback;
use function str_contains;

/**
 * spec/saml.md section 6.4 step 7, S-13 to S-16: the answer written with the model's objects, signed by the SAML key of
 * the tenant and turned into the form of HTTP-POST, read back as the service provider reads it, by PostReceiver and
 * saml2-model's ResponseValidator under the certificate the metadata publish.
 */
final class ModelSignOnResponderTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example/saml/metadata';

    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private TenantKey $key;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($this->key);
    }

    /**
     * S-15, section 6.4 step 7: the form posts to the endpoint the model resolved, the RelayState received given
     * back as it was.
     */
    #[Test]
    public function theFormPostsToTheEndpointWithTheRelayStateReceived(): void
    {
        // When
        $form = $this->responder()->success($this->tenant, self::response());

        // Then
        static::assertSame(
            [SignOnRequests::ASSERTION_CONSUMER, 'state-1'],
            [$form->action, $form->fields['RelayState'] ?? null],
        );
    }

    /**
     * S-15: the response and its assertion are both signed by the SAML key of the tenant, which the service
     * provider verifies under the certificate of the metadata.
     */
    #[Test]
    public function theResponseAndItsAssertionAreSigned(): void
    {
        // When
        $accepted = $this->accepted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertSame(SignatureCoverage::AssertionAndResponse, $accepted->coverage);
    }

    /**
     * S-37: the signature of the response and the one of its assertion each carry, in their KeyInfo, the one
     * certificate the metadata publish for the key that signed them.
     */
    #[Test]
    public function eachSignatureCarriesTheCertificateOfTheMetadata(): void
    {
        // Given
        $published = SamlKeys::published($this->keys, $this->tenant);

        // When
        $response = $this->posted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertSame([$published, $published], SignatureCertificates::of($response));
    }

    /**
     * S-37: the signature of a failure carries the same certificate.
     */
    #[Test]
    public function theSignatureOfAFailureCarriesTheCertificateOfTheMetadata(): void
    {
        // Given
        $published = SamlKeys::published($this->keys, $this->tenant);

        // When
        $response = $this->posted($this->responder()->failure(
            $this->tenant,
            new SignOnFailure(self::IDENTITY_PROVIDER, SignOnRequests::request(), SignOnStatus::NoPassive, Fixtures::now()),
        ));

        // Then
        static::assertSame([$published], SignatureCertificates::of($response));
    }

    /**
     * S-13: the persistent identifier, qualified by the identity provider and the service provider.
     */
    #[Test]
    public function theSubjectIsThePersistentIdentifierQualifiedByBothEntities(): void
    {
        // When
        $accepted = $this->accepted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertEquals(
            new NameId('alice-at-sp', NameIdFormat::Persistent, self::IDENTITY_PROVIDER, ServiceProviderDocuments::SIGNED),
            $accepted->assertion->nameId,
        );
    }

    /**
     * S-14: the assertion is addressed to the request that asked for it: its issuer, its audience, its recipient and
     * the request it answers.
     */
    #[Test]
    public function theAssertionIsAddressedToTheRequest(): void
    {
        // When
        $assertion = $this->accepted($this->responder()->success($this->tenant, self::response()))->assertion;

        // Then
        static::assertSame(
            [self::IDENTITY_PROVIDER, [[ServiceProviderDocuments::SIGNED]], SignOnRequests::ASSERTION_CONSUMER, SignOnRequests::ID],
            [$assertion->issuer->entityId, $assertion->conditions->audiences, $assertion->confirmation->recipient, $assertion->confirmation->inResponseTo],
        );
    }

    /**
     * S-15: valid five minutes from its issue, the NotBefore of its Conditions its IssueInstant, which Entra requires
     * (section 7).
     */
    #[Test]
    public function theAssertionIsValidFiveMinutesFromItsIssue(): void
    {
        // When
        $assertion = $this->accepted($this->responder()->success($this->tenant, self::response()))->assertion;

        // Then
        static::assertSame(
            ['2026-09-15T10:00:00+00:00', '2026-09-15T10:05:00+00:00', '2026-09-15T10:05:00+00:00', '2026-09-15T10:00:00+00:00'],
            [
                $assertion->conditions->notBefore?->format('c'),
                $assertion->conditions->notOnOrAfter?->format('c'),
                $assertion->confirmation->notOnOrAfter->format('c'),
                $assertion->issueInstant->format('c'),
            ],
        );
    }

    /**
     * Section 6.4 step 7: the session by its ID and its latest proof, and the unspecified class.
     */
    #[Test]
    public function theStatementIsOfTheSession(): void
    {
        // When
        $statement = $this->accepted($this->responder()->success($this->tenant, self::response()))->assertion->authnStatement;

        // Then
        static::assertSame(
            ['the-session', '2026-09-15T09:30:00+00:00', 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', null],
            [$statement->sessionIndex, $statement->authnInstant->format('c'), $statement->authnContextClassRef, $statement->sessionNotOnOrAfter],
        );
    }

    /**
     * S-16: the attributes released, under their mapping, without xsi:type.
     */
    #[Test]
    public function theAttributesAreTheOnesReleased(): void
    {
        // When
        $accepted = $this->accepted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertEquals(
            [new Attribute('urn:oid:0.9.2342.19200300.100.1.3', ModelAttributeNameFormat::Uri, 'mail', ['alice@example.com', 'alice@example.org'])],
            $accepted->assertion->attributes,
        );
    }

    /**
     * Section 6.4 steps 4 and 7: a failure carries its status and no assertion, to the same endpoint.
     */
    #[Test]
    public function aFailureCarriesItsStatus(): void
    {
        // Given
        $form = $this->responder()->failure(
            $this->tenant,
            new SignOnFailure(self::IDENTITY_PROVIDER, SignOnRequests::request(), SignOnStatus::NoPassive, Fixtures::now()),
        );

        // When
        try {
            $this->accepted($form);
            static::fail('A failure carries no assertion.');
        } catch (UnsuccessfulResponse $failure) {
            // Then
            static::assertSame(
                [StatusCode::Responder, SecondLevelStatusCode::NoPassive],
                [$failure->status->code, $failure->status->secondLevel],
            );
        }
    }

    /**
     * Section 6.4 step 7: a failure goes back with the RelayState received too.
     */
    #[Test]
    public function aFailureGivesTheRelayStateBack(): void
    {
        // When
        $form = $this->responder()->failure(
            $this->tenant,
            new SignOnFailure(self::IDENTITY_PROVIDER, SignOnRequests::request(), SignOnStatus::InvalidNameIdPolicy, Fixtures::now()),
        );

        // Then
        static::assertSame([SignOnRequests::ASSERTION_CONSUMER, 'state-1'], [$form->action, $form->fields['RelayState'] ?? null]);
    }

    /**
     * S-1: a tenant that holds no active SAML key signs nothing.
     */
    #[Test]
    public function aTenantWithoutAnActiveKeySignsNothing(): void
    {
        // Given
        $this->keys = new InMemoryTenantKeyRepository();

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->responder()->success($this->tenant, self::response());
    }

    /**
     * S-1, section 6.1 step 2: a private half that is not the one of the public JWK signs nothing, success or failure.
     */
    #[Test]
    #[DataProvider('provideAnswers')]
    public function aPrivateHalfThatIsNotTheKeysSignsNothing(Closure $answer): void
    {
        // Given
        $this->keyOf(SamlKeys::pair()->publicJwk, SamlKeys::otherPair()->privateJwk, SamlKeys::pair()->kid);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('one its own reader refuses (spec/saml.md section 6.4 step 7).');
        $this->expectExceptionCode(0);

        // When
        $answer($this->responder(), $this->tenant);
    }

    /**
     * D-16: a key Dsig refuses to sign with, under 2 048 bits, signs nothing, success or failure.
     */
    #[Test]
    #[DataProvider('provideAnswers')]
    public function aKeyDsigRefusesSignsNothing(Closure $answer): void
    {
        // Given
        $weak = SamlKeys::weakPair();
        $this->keyOf($weak->publicJwk, $weak->privateJwk, $weak->kid);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('one its own reader refuses (spec/saml.md section 6.4 step 7).');
        $this->expectExceptionCode(0);

        // When
        $answer($this->responder(), $this->tenant);
    }

    /**
     * @return iterable<string, array{Closure(ModelSignOnResponder, Tenant): PostedForm}>
     */
    public static function provideAnswers(): iterable
    {
        yield 'a success' => [static fn (ModelSignOnResponder $responder, Tenant $tenant): PostedForm => $responder->success($tenant, self::response())];
        yield 'a failure' => [
            static fn (ModelSignOnResponder $responder, Tenant $tenant): PostedForm => $responder->failure(
                $tenant,
                new SignOnFailure(self::IDENTITY_PROVIDER, SignOnRequests::request(), SignOnStatus::NoPassive, Fixtures::now()),
            ),
        ];
    }

    /**
     * S-19, S-21: for a response that names the certificate of a service provider, the response holds one
     * saml:EncryptedAssertion and no saml:Assertion, its own signature after its Issuer.
     */
    #[Test]
    public function theAssertionIsEncryptedForTheCertificateNamed(): void
    {
        // When
        $response = $this->posted($this->responder()->success($this->tenant, self::response(encrypted: true)));

        // Then
        static::assertSame(
            ['saml:Issuer', 'ds:Signature', 'samlp:Status', 'saml:EncryptedAssertion'],
            array_map(static fn (Element $child): string => $child->nodeName, Children::all($response->root())),
        );
    }

    /**
     * S-20: the content under aes256-gcm, the session key under rsa-oaep-mgf1p, no Algorithm of the response naming
     * CBC.
     */
    #[Test]
    public function theAssertionIsEncryptedUnderOneSchemeAndNothingInCbc(): void
    {
        // When
        $response = $this->posted($this->responder()->success($this->tenant, self::response(encrypted: true)));

        // Then
        $data = self::encryptedData($response);
        static::assertSame(
            ['http://www.w3.org/2009/xmlenc11#aes256-gcm', 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', []],
            [
                Attributes::required(Children::one($data, new Name(self::XMLENC, 'EncryptionMethod')), new Name(null, 'Algorithm')),
                Attributes::required(Children::one(self::encryptedKey($data), new Name(self::XMLENC, 'EncryptionMethod')), new Name(null, 'Algorithm')),
                self::cbcAlgorithms($response->root()),
            ],
        );
    }

    /**
     * S-19: the EncryptedKey carries no KeyInfo, the service provider decrypting with the key it holds.
     */
    #[Test]
    public function theEncryptedKeyCarriesNoKeyInfo(): void
    {
        // When
        $response = $this->posted($this->responder()->success($this->tenant, self::response(encrypted: true)));

        // Then
        static::assertNull(Children::optional(self::encryptedKey(self::encryptedData($response)), new Name(self::DSIG, 'KeyInfo')));
    }

    /**
     * S-19, S-21, SAML Core §6.2: decrypted with the private key of the certificate named, the assertion is the one the
     * tenant signed for the service provider: put back in place of its ciphertext, the signature of the response taken
     * off, the model's validator accepts it, the assertion covering itself.
     */
    #[Test]
    public function theDecryptedAssertionIsTheOneTheTenantSigned(): void
    {
        // Given
        $response = $this->posted($this->responder()->success($this->tenant, self::response(encrypted: true)));

        // When
        $accepted = $this->validate(UnverifiedResponse::of(SamlLoader::create()->load(self::decryptedInPlace($response))));

        // Then
        static::assertEquals(
            [SignatureCoverage::Assertion, new NameId('alice-at-sp', NameIdFormat::Persistent, self::IDENTITY_PROVIDER, ServiceProviderDocuments::SIGNED)],
            [$accepted->coverage, $accepted->assertion->nameId],
        );
    }

    /**
     * S-21: the signature of the response verifies under the certificate of the tenant over the ciphertext.
     */
    #[Test]
    public function theSignatureOfTheResponseVerifiesOverTheCiphertext(): void
    {
        // Given
        $response = $this->posted($this->responder()->success($this->tenant, self::response(encrypted: true)));

        // When
        $verified = new Verifier(SamlLoader::create())->verify($response->root(), $this->tenantKeys());

        // Then
        static::assertCount(1, Children::named($verified->document->root(), new Name(self::ASSERTION, 'EncryptedAssertion')));
    }

    /**
     * S-21: a byte of the ciphertext changed, the signature of the response no longer holds, so that the service
     * provider refuses it before it decrypts anything.
     */
    #[Test]
    public function theSignatureOfTheResponseCoversTheCiphertext(): void
    {
        // Given
        $bytes = (string) base64_decode($this->responder()->success($this->tenant, self::response(encrypted: true))->fields['SAMLResponse'], true);
        $altered = SamlLoader::create()->load((string) preg_replace_callback(
            '~(</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>)(.)~',
            static fn (array $match): string => $match[1] . ($match[2] === 'A' ? 'B' : 'A'),
            $bytes,
        ));

        // Then
        $this->expectException(DigestMismatch::class);

        // When
        new Verifier(SamlLoader::create())->verify($altered->root(), $this->tenantKeys());
    }

    /**
     * The only active SAML key of the tenant, on the halves given.
     *
     * @param array<string, string> $publicJwk
     * @param array<string, string> $privateJwk
     */
    private function keyOf(array $publicJwk, array $privateJwk, string $kid): void
    {
        $key = new TenantKey(
            $kid,
            $this->tenant,
            SamlKeys::algorithm(),
            $publicJwk,
            Keys::sealer()->seal($this->tenant, $privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($key);
    }

    private function responder(): ModelSignOnResponder
    {
        return new ModelSignOnResponder(SamlKeys::signing($this->keys));
    }

    private function accepted(PostedForm $form): AcceptedAssertion
    {
        return $this->validate(new PostReceiver(SamlLoader::create())->response($form->fields)->response);
    }

    /**
     * The response the form posts, loaded as the service provider loads it.
     */
    private function posted(PostedForm $form): Document
    {
        return SamlLoader::create()->load((string) base64_decode($form->fields['SAMLResponse'], true));
    }

    /**
     * The certificate the metadata of the tenant publish, as Dsig verifies under it.
     */
    private function tenantKeys(): VerificationKeys
    {
        return new VerificationKeys([VerificationKey::fromCertificateBase64(
            new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key))->base64,
        )]);
    }

    /**
     * The response as the service provider reads it once it decrypted its assertion with the test key of a service
     * provider of saml2-model: the plaintext in place of the saml:EncryptedAssertion, the signature of the response,
     * which covered the ciphertext, taken off.
     */
    private static function decryptedInPlace(Document $response): string
    {
        $plaintext = new Decryptor(SamlLoader::create())->decrypt(
            self::encryptedData($response),
            PrivateDecryptionKey::fromPem(MetadataFixtures::bytes('keys/sp-signing-key.pem')),
        );
        $assertion = (string) preg_replace('~^<\?xml[^>]*\?>\s*~', '', new Serializer()->serialize($plaintext));
        $bytes = (string) preg_replace('~(</saml:Issuer>)<ds:Signature\b.*?</ds:Signature>~s', '$1', new Serializer()->serialize($response), 1);

        return (string) preg_replace_callback(
            '~<saml:EncryptedAssertion\b.*</saml:EncryptedAssertion>~s',
            static fn (): string => $assertion,
            $bytes,
        );
    }

    private static function encryptedData(Document $response): Element
    {
        return Children::one(
            Children::one($response->root(), new Name(self::ASSERTION, 'EncryptedAssertion')),
            new Name(self::XMLENC, 'EncryptedData'),
        );
    }

    private static function encryptedKey(Element $data): Element
    {
        return Children::one(Children::one($data, new Name(self::DSIG, 'KeyInfo')), new Name(self::XMLENC, 'EncryptedKey'));
    }

    /**
     * The Algorithm attributes under the root that name CBC, read from the attributes and never from the serialized
     * response, whose base64 spells any three letters at random.
     *
     * @return list<string>
     */
    private static function cbcAlgorithms(Element $root): array
    {
        $named = [];
        foreach ($root->getElementsByTagName('*') as $element) {
            $algorithm = $element->getAttribute('Algorithm');
            if ($algorithm !== null && str_contains($algorithm, 'cbc')) {
                $named[] = $algorithm;
            }
        }

        return $named;
    }

    private function validate(UnverifiedResponse $response): AcceptedAssertion
    {
        $certificate = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key));

        return new ResponseValidator(SamlLoader::create(), new FrozenClock(Fixtures::now()), new InMemoryReplayGuard())->validate(
            $response,
            new IdentityProvider(
                self::IDENTITY_PROVIDER,
                [$certificate->base64],
                [],
                [
                    new Endpoint(Binding::HttpRedirect, 'https://id.acme.example/saml/sso'),
                ],
            ),
            ExpectedResponse::toRequest(SignOnRequests::ID, SignOnRequests::ASSERTION_CONSUMER, ServiceProviderDocuments::SIGNED),
        );
    }

    private static function response(bool $encrypted = false): SignOnResponse
    {
        return new SignOnResponse(
            self::IDENTITY_PROVIDER,
            SignOnRequests::request(),
            new PersistentNameId('alice-at-sp'),
            [new ReleasedAttribute('urn:oid:0.9.2342.19200300.100.1.3', AttributeNameFormat::Uri, 'mail', array_map(
                static fn (string $value): AttributeValue => new AttributeValue($value),
                ['alice@example.com', 'alice@example.org'],
            ))],
            'the-session',
            Fixtures::now()->modify('-30 minutes'),
            Fixtures::now(),
            $encrypted ? new Certificate(MetadataFixtures::certificate('sp')) : null,
        );
    }
}
