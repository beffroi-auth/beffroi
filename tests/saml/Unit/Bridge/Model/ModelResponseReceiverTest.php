<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Bridge\Model\ModelResponseReceiver;
use Beffroi\Saml\Bridge\Model\ModelUpstreamMetadataReader;
use Beffroi\Saml\Bridge\Model\UpstreamDecryptionKeys;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\VerifiedAssertion;
use Beffroi\Saml\Exception\AssertionRefusedException;
use Beffroi\Saml\Exception\UpstreamAuthenticationFailedException;
use Beffroi\Saml\Tests\Fixture\FixedServiceProviderEndpoints;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\InMemoryReplayStore;
use Beffroi\Saml\Tests\Fixture\SamlEncryption;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\UpstreamResponses;
use Beffroi\Saml\Tests\Fixture\WiredAlgorithmsOf;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Xml\Enc\PeerKey;
use function array_key_exists;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-53, section 6.14 step 3, model.md section 6.1: the response an upstream identity provider posts, read
 * by saml2-bindings and validated by saml2-model under the accepted document of the provider the request went to, as
 * the answer to that request, received at the assertion consumer service of the tenant for its entity ID, once. The
 * responses are written and signed by saml2-model's writer with the test key of an identity provider of its suite,
 * the one the accepted document publishes (IdentityProviderDocuments::signingOnAt()).
 */
final class ModelResponseReceiverTest extends TestCase
{
    private const string REQUEST = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    private const string ASSERTION_CONSUMER_SERVICE = 'https://id.acme.example/saml/sp/acs';

    private const string AUDIENCE = 'https://id.acme.example/saml/sp/metadata';

    private Tenant $tenant;

    private InMemoryAcceptedMetadata $accepted;

    private MockClock $clock;

    private InMemoryTenantKeyRepository $keys;

    private ModelResponseReceiver $receiver;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->accepted = new InMemoryAcceptedMetadata();
        $this->clock = new MockClock('2026-10-23T09:00:00+00:00');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->receiver = new ModelResponseReceiver(
            $this->accepted,
            new ModelUpstreamMetadataReader($this->clock),
            new UpstreamDecryptionKeys(
                $this->keys,
                new WiredAlgorithmsOf([new SamlEncryption(IdentityProviderDocuments::SIGNED)]),
                new SealedKeyProvider($this->keys, Keys::opened()),
            ),
            new FixedServiceProviderEndpoints(),
            new InMemoryReplayStore(),
            $this->clock,
        );
        $this->accepted->save(new AcceptedUpstreamMetadata(
            Uuid::v7(),
            $this->tenant,
            IdentityProviderDocuments::SIGNED,
            IdentityProviderDocuments::signingOnAt([new Endpoint(Binding::HttpRedirect, IdentityProviderDocuments::SIGNED . '/sso')]),
            null,
            Fixtures::now(),
        ));
    }

    /**
     * The acceptance of issue #784, S-53, Profiles §4.1.4.5: a response signed by the provider, for the request it
     * answers, is read into what the model accepted of it, the values of each attribute by its name.
     */
    #[Test]
    public function aResponseOfTheProviderForTheRequestItAnswersIsAccepted(): void
    {
        // Given
        $form = $this->form(attributes: [
            'mail' => ['alice@acme.example'],
            'eduPersonAffiliation' => ['member', 'staff'],
        ], sessionNotOnOrAfter: $this->clock->now()->modify('+8 hours'));

        // When
        $verified = $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);

        // Then
        static::assertEquals(
            new VerifiedAssertion(
                'a7f3c2e1-persistent-alice',
                true,
                [
                    'mail' => ['alice@acme.example'],
                    'eduPersonAffiliation' => ['member', 'staff'],
                ],
                $this->clock->now(),
                UpstreamResponses::PASSWORD_PROTECTED_TRANSPORT,
                false,
                $this->clock->now()->modify('+8 hours'),
            ),
            $verified,
        );
    }

    /**
     * Section 6.1 step 11 of model.md: an attribute named twice, as Keycloak sends one per value, is one attribute of
     * the person, its values in document order.
     */
    #[Test]
    public function anAttributeNamedTwiceIsOneAttribute(): void
    {
        // Given
        $form = $this->form(attributes: [
            'eduPersonAffiliation' => ['member'],
            'mail' => ['alice@acme.example'],
        ], repeated: ['eduPersonAffiliation' => ['staff']]);

        // When
        $verified = $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);

        // Then
        static::assertSame(['member', 'staff'], $verified->values('eduPersonAffiliation'));
    }

    /**
     * S-66, S-54, M-18: an assertion the provider encrypted for the certificate its metadata publish is opened by the
     * key of that provider, given to the model with it, and said to have arrived encrypted.
     */
    #[Test]
    public function anAssertionEncryptedForTheProviderIsOpenedWithItsKey(): void
    {
        // Given
        $this->keys->save(SamlKeys::encryptionKey($this->tenant, IdentityProviderDocuments::SIGNED));
        $certificates = new EncryptionCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer())->of(
            $this->tenant,
            IdentityProviderDocuments::SIGNED,
        );
        $form = UpstreamResponses::form(
            MetadataFixtures::signingKey('idp'),
            IdentityProviderDocuments::SIGNED,
            self::ASSERTION_CONSUMER_SERVICE,
            self::AUDIENCE,
            self::REQUEST,
            $this->clock->now(),
            ['mail' => ['alice@acme.example']],
            encryption: new Encryption(PeerKey::fromCertificateBase64($certificates[0]->base64)),
        );

        // When
        $verified = $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);

        // Then
        static::assertSame([true, ['alice@acme.example']], [$verified->encrypted, $verified->values('mail')]);
    }

    /**
     * S-55, Core §8.3.7: whether the NameID is persistent is read from its format, any other being none.
     */
    #[Test]
    public function aNameIdOfAnotherFormatIsNotPersistent(): void
    {
        // Given
        $form = $this->form(nameId: new NameId('alice@acme.example'));

        // When
        $verified = $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);

        // Then
        static::assertSame(['alice@acme.example', false], [$verified->nameId, $verified->persistent]);
    }

    /**
     * The acceptance of issue #784, S-53, M-8, M-10, M-11, M-3: a response refused by the model under the accepted
     * document and the request remembered, its message the one of the rule, naming no value (M-16).
     *
     * @param array{issuer?: string, key?: 'idp'|'sp', inResponseTo?: string|null, audience?: string} $change
     */
    #[Test]
    #[DataProvider('provideResponsesTheModelRefuses')]
    public function aResponseTheModelRefusesIsRefused(array $change, string $message): void
    {
        // Given
        $form = $this->form(
            issuer: $change['issuer'] ?? IdentityProviderDocuments::SIGNED,
            key: $change['key'] ?? 'idp',
            inResponseTo: array_key_exists('inResponseTo', $change) ? $change['inResponseTo'] : self::REQUEST,
            audience: $change['audience'] ?? self::AUDIENCE,
        );

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);
    }

    /**
     * @return iterable<string, array{array{issuer?: string, key?: 'idp'|'sp', inResponseTo?: string|null, audience?: string}, string}>
     */
    public static function provideResponsesTheModelRefuses(): iterable
    {
        yield 'another InResponseTo' => [
            ['inResponseTo' => '_ffffffffffffffffffffffffffffffffffffffff'],
            'The InResponseTo of the response is not the one the consumer expects (M-10).',
        ];
        yield 'an unsolicited response' => [['inResponseTo' => null], 'The InResponseTo of the response is not the one the consumer expects (M-10).'];
        yield 'another audience' => [
            ['audience' => 'https://another.example/saml/sp/metadata'],
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'another provider' => [['issuer' => 'https://idp.other.example/saml'], 'The Issuer is not the entity ID of the peer (M-8).'];
        yield 'a key outside the metadata' => [['key' => 'sp'], 'No trusted key verifies the signature over SignedInfo (D-7, D-8).'];
    }

    /**
     * S-58, model.md M-13, Core §3.2.2.2: a response whose status is not Success, held to the request it answers, is an
     * authentication the provider failed, which says whether it is NoPassive and nothing else of it.
     */
    #[Test]
    #[DataProvider('provideFailures')]
    public function aResponseWhoseStatusIsNotSuccessIsAFailedAuthentication(SecondLevelStatusCode $secondLevel, bool $noPassive): void
    {
        // Given
        $form = UpstreamResponses::failure(
            MetadataFixtures::signingKey('idp'),
            IdentityProviderDocuments::SIGNED,
            self::ASSERTION_CONSUMER_SERVICE,
            self::REQUEST,
            $this->clock->now(),
            $secondLevel,
        );

        // When
        try {
            $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);
            static::fail('The failure was taken.');
        } catch (UpstreamAuthenticationFailedException $failure) {
            // Then
            static::assertSame(['The identity provider authenticated nobody (spec/saml.md S-58).', $noPassive, null], [
                $failure->getMessage(),
                $failure->noPassive,
                $failure->getPrevious(),
            ]);
        }
    }

    /**
     * @return iterable<string, array{SecondLevelStatusCode, bool}>
     */
    public static function provideFailures(): iterable
    {
        yield 'AuthnFailed' => [SecondLevelStatusCode::AuthnFailed, false];
        yield 'RequestDenied' => [SecondLevelStatusCode::RequestDenied, false];
        yield 'NoPassive' => [SecondLevelStatusCode::NoPassive, true];
    }

    /**
     * S-58, M-10: a failure for another request is refused for its InResponseTo, and is no failure of this one.
     */
    #[Test]
    public function aFailureForAnotherRequestIsRefused(): void
    {
        // Given
        $form = UpstreamResponses::failure(
            MetadataFixtures::signingKey('idp'),
            IdentityProviderDocuments::SIGNED,
            self::ASSERTION_CONSUMER_SERVICE,
            '_ffffffffffffffffffffffffffffffffffffffff',
            $this->clock->now(),
            SecondLevelStatusCode::AuthnFailed,
        );

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The InResponseTo of the response is not the one the consumer expects (M-10).');

        // When
        $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);
    }

    /**
     * The acceptance of issue #784, S-53, M-11: the same assertion presented a second time is refused by the replay
     * store, whatever request it claims to answer.
     */
    #[Test]
    public function anAssertionPresentedTwiceIsRefused(): void
    {
        // Given
        $form = $this->form(assertionId: '_assertion-presented-twice');
        $this->receiver->receive($this->tenant, self::provider(), $form, self::REQUEST);

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The assertion was already accepted from its issuer (M-11).');

        // When
        $this->receiver->receive($this->tenant, self::provider(), $this->form(assertionId: '_assertion-presented-twice'), self::REQUEST);
    }

    /**
     * S-53, S-42: a provider whose document was never accepted, or was forgotten, takes nothing.
     */
    #[Test]
    public function aProviderWithNoAcceptedDocumentIsRefused(): void
    {
        // Given
        $provider = self::provider('https://idp.never-accepted.example/saml');

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The identity provider has no metadata accepted (spec/saml.md S-53).');

        // When
        $this->receiver->receive($this->tenant, $provider, $this->form(), self::REQUEST);
    }

    /**
     * S-53, S-43: a document accepted before that the reading back refuses now, here one whose role holds no key to
     * verify by, takes nothing, its refusal naming the rule.
     */
    #[Test]
    public function aDocumentTheReadingBackRefusesIsRefused(): void
    {
        // Given
        $this->accepted->save(new AcceptedUpstreamMetadata(
            Uuid::v7(),
            $this->tenant,
            IdentityProviderDocuments::SIMPLESAMLPHP,
            IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey(),
            null,
            Fixtures::now(),
        ));

        // Then
        $this->expectException(AssertionRefusedException::class);
        $this->expectExceptionMessageIs('The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).');

        // When
        $this->receiver->receive($this->tenant, self::provider(IdentityProviderDocuments::SIMPLESAMLPHP), $this->form(), self::REQUEST);
    }

    /**
     * @param array<string, list<string>> $attributes
     * @param array<string, list<string>> $repeated attributes written a second time, after the others
     * @param 'idp'|'sp' $key
     *
     * @return array<string, string>
     */
    private function form(
        array $attributes = ['mail' => ['alice@acme.example']],
        array $repeated = [],
        string $issuer = IdentityProviderDocuments::SIGNED,
        string $key = 'idp',
        ?string $inResponseTo = self::REQUEST,
        string $audience = self::AUDIENCE,
        NameId $nameId = new NameId('a7f3c2e1-persistent-alice', NameIdFormat::Persistent),
        ?string $assertionId = null,
        ?DateTimeImmutable $sessionNotOnOrAfter = null,
    ): array {
        return UpstreamResponses::form(
            MetadataFixtures::signingKey($key),
            $issuer,
            self::ASSERTION_CONSUMER_SERVICE,
            $audience,
            $inResponseTo,
            $this->clock->now(),
            $attributes,
            nameId: $nameId,
            assertionId: $assertionId,
            repeated: $repeated,
            sessionNotOnOrAfter: $sessionNotOnOrAfter,
        );
    }

    private static function provider(string $entityId = IdentityProviderDocuments::SIGNED): UpstreamIdentityProvider
    {
        return new UpstreamIdentityProvider(
            $entityId,
            new MetadataLocation('https://idp.acme.example/metadata'),
            [],
            [new EmailDomain('acme.example')],
            'mail',
        );
    }
}
