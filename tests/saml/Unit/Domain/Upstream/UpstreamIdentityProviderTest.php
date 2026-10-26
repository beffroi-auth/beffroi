<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use function array_fill;
use function array_map;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Saml\Domain\Upstream\GroupMapping;
use Beffroi\Saml\Domain\Upstream\ProfileAttribute;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function sprintf;
use function str_repeat;

/**
 * spec/saml.md S-42, S-44, S-45, section 6.10 step 1: the declaration of an upstream identity provider holds together
 * or is refused.
 */
final class UpstreamIdentityProviderTest extends TestCase
{
    private const string ENTITY_ID = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

    private const string OBJECT_ID = 'http://schemas.microsoft.com/identity/claims/objectidentifier';

    /**
     * S-42, S-45: a declaration holds what it was given, its subject and its groups when declared.
     */
    #[Test]
    public function aDeclarationHoldsWhatItWasGiven(): void
    {
        // Given
        $groups = new GroupMapping('groups', ['member' => 'Members']);

        // When
        $identityProvider = new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            [new EmailDomain('acme.example')],
            'mail',
            [new ProfileAttribute('givenName', 'given_name')],
            self::OBJECT_ID,
            $groups,
        );

        // Then
        static::assertSame(self::ENTITY_ID, $identityProvider->entityId);
        static::assertSame('/srv/saml/idp.xml', $identityProvider->metadata->value);
        static::assertSame('acme.example', $identityProvider->domains[0]->value);
        static::assertSame('mail', $identityProvider->emailAttribute);
        static::assertSame('given_name', $identityProvider->profile[0]->claim);
        static::assertSame(self::OBJECT_ID, $identityProvider->subjectAttribute);
        static::assertSame($groups, $identityProvider->groups);
    }

    /**
     * S-60: a declaration is the upstream provider of the core named by its entity ID, answering for its domains and
     * filling the claims of its profile, so that every place that reads a domain reads it by the one rule of the core.
     */
    #[Test]
    public function aDeclarationIsTheUpstreamProviderOfTheCoreItNames(): void
    {
        // Given
        $identityProvider = new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            [new EmailDomain('acme.example'), new EmailDomain('xn--bcher-kva.example')],
            'mail',
            [new ProfileAttribute('givenName', 'given_name'), new ProfileAttribute('sn', 'family_name')],
        );

        // When
        $provider = $identityProvider->provider();

        // Then
        static::assertEquals(
            new UpstreamProvider(
                self::ENTITY_ID,
                [new EmailDomain('acme.example'), new EmailDomain('xn--bcher-kva.example')],
                ['given_name', 'family_name'],
            ),
            $provider,
        );
    }

    /**
     * S-60, S-45: a telephone number an attribute fills is no claim of the profile of the core, and the declaration that
     * fills one is a provider of the core all the same, filling the claims of the profile it names.
     */
    #[Test]
    public function aTelephoneNumberIsNoClaimOfTheProviderOfTheCore(): void
    {
        // Given
        $identityProvider = new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            [new EmailDomain('acme.example')],
            'mail',
            [new ProfileAttribute('telephoneNumber', 'phone_number'), new ProfileAttribute('givenName', 'given_name')],
        );

        // When
        $provider = $identityProvider->provider();

        // Then
        static::assertSame(['given_name'], $provider->claims);
    }

    /**
     * S-45: the attribute of the subject and the groups are optional, the profile empty unless declared.
     */
    #[Test]
    public function theSubjectTheProfileAndTheGroupsAreOptional(): void
    {
        // When
        $identityProvider = self::declaration([new EmailDomain('acme.example')]);

        // Then
        static::assertSame([], $identityProvider->profile);
        static::assertNull($identityProvider->subjectAttribute);
        static::assertNull($identityProvider->groups);
    }

    /**
     * S-42: the metadata are read signed when the declaration pins a signer, and trusted by their channel otherwise.
     */
    #[Test]
    public function theMetadataAreReadSignedWhenASignerIsPinned(): void
    {
        // Given
        $identityProvider = new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [IdentityProviderDocuments::signer()],
            [new EmailDomain('acme.example')],
            'mail',
        );

        // When / Then
        static::assertTrue($identityProvider->readsSigned());
    }

    /**
     * S-42: no signer pinned, the metadata are trusted by their channel.
     */
    #[Test]
    public function theMetadataAreTrustedByTheirChannelWithoutASigner(): void
    {
        // When / Then
        static::assertFalse(self::declaration([new EmailDomain('acme.example')])->readsSigned());
    }

    /**
     * Section 7: sixteen signers of the metadata at most.
     */
    #[Test]
    public function seventeenSignersAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An identity provider pins at most 16 signers of its metadata (spec/saml.md section 7).');

        // When
        new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            array_fill(0, 17, IdentityProviderDocuments::signer()),
            [new EmailDomain('acme.example')],
            'mail',
        );
    }

    /**
     * Section 7: sixteen signers of the metadata are pinned.
     */
    #[Test]
    public function sixteenSignersArePinned(): void
    {
        // When
        $identityProvider = new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            array_fill(0, 16, IdentityProviderDocuments::signer()),
            [new EmailDomain('acme.example')],
            'mail',
        );

        // Then
        static::assertCount(16, $identityProvider->metadataSigners);
    }

    /**
     * S-44: an identity provider answers for one domain at least.
     */
    #[Test]
    public function noDomainIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An identity provider answers for one e-mail domain at least (spec/saml.md S-44).');

        // When
        self::declaration([]);
    }

    /**
     * Section 7: 256 domains at most.
     */
    #[Test]
    public function moreThan256DomainsAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An identity provider answers for 256 e-mail domains at most (spec/saml.md section 7).');

        // When
        self::declaration(self::domains(257));
    }

    /**
     * Section 7: 256 domains are declared.
     */
    #[Test]
    public function twoHundredAndFiftySixDomainsAreDeclared(): void
    {
        // When / Then
        static::assertCount(256, self::declaration(self::domains(256))->domains);
    }

    /**
     * S-44: a domain declared twice by one provider, in two spellings, is refused.
     */
    #[Test]
    public function aDomainDeclaredTwiceIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The domain "acme.example" is declared twice (spec/saml.md S-44).');

        // When
        self::declaration([new EmailDomain('acme.example'), new EmailDomain('ACME.example')]);
    }

    /**
     * S-45: the attributes of the e-mail and of the subject are names.
     */
    #[Test]
    #[DataProvider('provideAttributesThatAreNoName')]
    public function anAttributeThatIsNoNameIsRefused(string $email, ?string $subject, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new UpstreamIdentityProvider(self::ENTITY_ID, new MetadataLocation('/srv/saml/idp.xml'), [], [new EmailDomain('acme.example')], $email, [], $subject);
    }

    /**
     * @return iterable<string, array{string, ?string, string}>
     */
    public static function provideAttributesThatAreNoName(): iterable
    {
        yield 'no attribute of the e-mail' => [
            '',
            null,
            'The attribute of the e-mail is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).',
        ];
        yield 'an attribute of the subject with a space' => [
            'mail',
            'object identifier',
            'The attribute of the subject is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).',
        ];
    }

    /**
     * S-45: the attribute of the subject is never the attribute of the e-mail, an address being given again to
     * another person.
     */
    #[Test]
    public function aSubjectNamedByTheAttributeOfTheEmailIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The attribute of the subject is the attribute of the e-mail, and an address is given again to another person (spec/saml.md S-45).');

        // When
        new UpstreamIdentityProvider(self::ENTITY_ID, new MetadataLocation('/srv/saml/idp.xml'), [], [new EmailDomain('acme.example')], 'mail', [], 'mail');
    }

    /**
     * S-45: one attribute per claim of the profile.
     */
    #[Test]
    public function twoAttributesFillingOneClaimAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The claim "given_name" is filled by two attributes (spec/saml.md S-45).');

        // When
        new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            [new EmailDomain('acme.example')],
            'mail',
            [new ProfileAttribute('givenName', 'given_name'), new ProfileAttribute('firstName', 'given_name')],
        );
    }

    /**
     * S-45: an attribute fills the profile once.
     */
    #[Test]
    public function oneAttributeFillingTwoClaimsIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The attribute "displayName" fills the profile twice (spec/saml.md S-45).');

        // When
        new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            [new EmailDomain('acme.example')],
            'mail',
            [new ProfileAttribute('displayName', 'name'), new ProfileAttribute('displayName', 'nickname')],
        );
    }

    /**
     * S-42: an identity provider declared under the entity ID of the identity provider of the tenant is refused, the
     * tenant never being upstream of itself.
     */
    #[Test]
    public function theEntityIdOfTheIdentityProviderOfTheTenantIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The identity provider "https://op.test/saml/metadata" is declared under the entity ID of the identity provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).');

        // When
        UpstreamIdentityProvider::assertNotTheTenant('https://op.test/saml/metadata', 'https://op.test/saml/metadata', 'https://op.test/saml/sp/metadata');
    }

    /**
     * S-42, S-38: an identity provider declared under the entity ID of the service provider of the tenant is refused,
     * one entity ID never naming two roles.
     */
    #[Test]
    public function theEntityIdOfTheServiceProviderOfTheTenantIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The identity provider "https://op.test/saml/sp/metadata" is declared under the entity ID of the service provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).');

        // When
        UpstreamIdentityProvider::assertNotTheTenant('https://op.test/saml/sp/metadata', 'https://op.test/saml/metadata', 'https://op.test/saml/sp/metadata');
    }

    /**
     * S-42: an entity ID that is none of the tenant's, or compared with entity IDs not known yet, is accepted.
     *
     */
    #[Test]
    #[DataProvider('provideEntityIdsOfAnother')]
    public function anEntityIdOfAnotherIsAccepted(string $entityId, ?string $identityProvider, ?string $serviceProvider): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        UpstreamIdentityProvider::assertNotTheTenant($entityId, $identityProvider, $serviceProvider);
    }

    /**
     * @return iterable<string, array{string, ?string, ?string}>
     */
    public static function provideEntityIdsOfAnother(): iterable
    {
        yield 'another entity' => [self::ENTITY_ID, 'https://op.test/saml/metadata', 'https://op.test/saml/sp/metadata'];
        yield 'a trailing slash' => ['https://op.test/saml/metadata/', 'https://op.test/saml/metadata', 'https://op.test/saml/sp/metadata'];
        yield 'entity IDs not known yet' => ['https://op.test/saml/metadata', null, null];
    }

    /**
     * S-68: a declaration names no parameter of the address unless it says so, so that nothing is sent to a provider
     * that does not read one.
     */
    #[Test]
    public function noParameterOfTheAddressIsNamedUnlessDeclared(): void
    {
        // When
        $identityProvider = self::declaration([new EmailDomain('acme.example')]);

        // Then
        static::assertNull($identityProvider->addressParameter);
    }

    /**
     * S-68, section 6.10 step 1: a parameter of the address that is a parameter of the binding is refused with the
     * declaration.
     */
    #[Test]
    public function aParameterOfTheAddressTheBindingHoldsIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The parameter of the address "RelayState" is a parameter of the binding (spec/saml.md S-68).');

        // When
        self::declaration([new EmailDomain('acme.example')], 'RelayState');
    }

    /**
     * S-68, section 6.10 step 1: a parameter of the address that is no token of a query is refused with the
     * declaration.
     */
    #[Test]
    public function aParameterOfTheAddressThatIsNoTokenIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The parameter of the address is one to 64 unreserved characters of RFC 3986 (spec/saml.md S-68).');

        // When
        self::declaration([new EmailDomain('acme.example')], 'login hint');
    }

    /**
     * S-68, S-60: the hint of an address of a domain the provider answers for is the parameter it declares and the
     * address, its domain written as its A-label and its local part as it was given.
     */
    #[Test]
    #[DataProvider('provideAddressesOfItsDomains')]
    public function theHintOfAnAddressOfItsDomainIsBuilt(string $given, string $address): void
    {
        // Given
        $identityProvider = self::declaration([new EmailDomain('acme.example'), new EmailDomain('xn--bcher-kva.example')], 'login_hint');

        // When
        $hint = $identityProvider->addressHint($given);

        // Then
        static::assertSame(['login_hint', $address], [$hint?->parameter, $hint?->address->value]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAddressesOfItsDomains(): iterable
    {
        yield 'as it is declared' => ['alice@acme.example', 'alice@acme.example'];
        yield 'in capitals' => ['Alice@ACME.example', 'Alice@acme.example'];
        yield 'in a U-label' => ['alice@Bücher.example', 'alice@xn--bcher-kva.example'];
        yield 'in its A-label' => ['alice@xn--bcher-kva.example', 'alice@xn--bcher-kva.example'];
    }

    /**
     * S-68: no hint for a provider that names no parameter, without an address, for an address the core does not
     * read, and for an address of a domain the provider does not answer for, a subdomain among them.
     */
    #[Test]
    #[DataProvider('provideAddressesWithoutAHint')]
    public function noHintIsBuilt(?string $parameter, ?string $given): void
    {
        // Given
        $identityProvider = self::declaration([new EmailDomain('acme.example')], $parameter);

        // When / Then
        static::assertNull($identityProvider->addressHint($given));
    }

    /**
     * @return iterable<string, array{?string, ?string}>
     */
    public static function provideAddressesWithoutAHint(): iterable
    {
        yield 'a provider that names no parameter' => [null, 'alice@acme.example'];
        yield 'no address' => ['login_hint', null];
        yield 'a username' => ['login_hint', 'alice'];
        yield 'a domain the rule refuses' => ['login_hint', 'alice@acme.example.'];
        yield 'a local part the core refuses' => ['login_hint', 'alice smith@acme.example'];
        yield 'a local part of 65 characters' => ['login_hint', str_repeat('a', 65) . '@acme.example'];
        yield 'another domain' => ['login_hint', 'alice@other.example'];
        yield 'a subdomain' => ['login_hint', 'alice@eu.acme.example'];
    }

    /**
     * @param list<EmailDomain> $domains
     */
    private static function declaration(array $domains, ?string $addressParameter = null): UpstreamIdentityProvider
    {
        return new UpstreamIdentityProvider(
            self::ENTITY_ID,
            new MetadataLocation('/srv/saml/idp.xml'),
            [],
            $domains,
            'mail',
            addressParameter: $addressParameter,
        );
    }

    /**
     * @return list<EmailDomain>
     */
    private static function domains(int $count): array
    {
        return array_map(static fn (int $index): EmailDomain => new EmailDomain(sprintf('d%d.example', $index)), range(1, $count));
    }
}
