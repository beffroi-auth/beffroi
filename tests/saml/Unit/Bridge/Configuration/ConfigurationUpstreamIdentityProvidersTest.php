<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Configuration;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Tests\Fixture\FixedProfileClaims;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-42, S-44, S-45, section 6.10 step 1: the upstream identity providers the configuration of the
 * deployment declares, keyed by entity ID, validated when they are built, those of one tenant.
 */
final class ConfigurationUpstreamIdentityProvidersTest extends TestCase
{
    private const string ENTRA = 'https://sts.windows.net/aaaabbbb-0000-cccc-1111-dddd2222eeee/';

    /**
     * S-42, S-45: a declaration is read whole into its UpstreamIdentityProvider.
     */
    #[Test]
    public function aDeclarationIsReadWhole(): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            [
                self::ENTRA => [
                    'metadata' => 'https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/federationmetadata/2007-06/federationmetadata.xml',
                    'metadata_signers' => [IdentityProviderDocuments::signer()->base64],
                    'domains' => ['Acme.example', 'acme-corp.example'],
                    'email_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                    'profile' => [
                        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' => 'given_name',
                        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname' => 'family_name',
                    ],
                    'subject_attribute' => 'http://schemas.microsoft.com/identity/claims/objectidentifier',
                    'groups' => [
                        'attribute' => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
                        'map' => [
                            '9f5c2a7e-1b3d-4e8f-a6c0-2d7b9e1f4a35' => 'Engineering',
                        ],
                    ],
                ],
            ],
            new FixedProfileClaims(),
        );

        // When
        $identityProvider = $identityProviders->find(Fixtures::tenant('acme'), self::ENTRA) ?? static::fail('The identity provider is not declared.');

        // Then
        static::assertSame(self::ENTRA, $identityProvider->entityId);
        static::assertTrue($identityProvider->readsSigned());
        static::assertSame(['acme.example', 'acme-corp.example'], [$identityProvider->domains[0]->value, $identityProvider->domains[1]->value]);
        static::assertSame('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', $identityProvider->emailAttribute);
        static::assertSame(['given_name', 'family_name'], [$identityProvider->profile[0]->claim, $identityProvider->profile[1]->claim]);
        static::assertSame('http://schemas.microsoft.com/identity/claims/objectidentifier', $identityProvider->subjectAttribute);
        static::assertSame('Engineering', $identityProvider->groups?->groupOf('9f5c2a7e-1b3d-4e8f-a6c0-2d7b9e1f4a35'));
    }

    /**
     * S-44, the acceptance of issue #779: a domain two identity providers of the tenant declare is refused, naming it
     * and both, whatever the case each writes it in.
     */
    #[Test]
    public function aDomainDeclaredByTwoIdentityProvidersIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The domain "acme.example" is declared by the identity providers "https://idp.acme.example/saml" and "https://idp.other.example/saml", and a domain answers to one provider (spec/saml.md S-44).');

        // When
        new ConfigurationUpstreamIdentityProviders(
            'acme',
            [
                'https://idp.acme.example/saml' => self::declaration(['acme.example']),
                'https://idp.other.example/saml' => self::declaration(['other.example', 'ACME.example']),
            ],
            new FixedProfileClaims(),
        );
    }

    /**
     * S-44: two identity providers of distinct domains are both declared, a subdomain being a domain of its own.
     */
    #[Test]
    public function twoIdentityProvidersOfDistinctDomainsAreDeclared(): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            [
                'https://idp.acme.example/saml' => self::declaration(['acme.example']),
                'https://idp.eu.acme.example/saml' => self::declaration(['eu.acme.example']),
            ],
            new FixedProfileClaims(),
        );

        // When / Then
        static::assertCount(2, $identityProviders->of(Fixtures::tenant('acme')));
    }

    /**
     * S-45: an attribute filling a claim the profile of a person does not hold in this deployment is refused, the
     * e-mail among them, which has its own attribute.
     */
    #[Test]
    public function aClaimTheProfileDoesNotHoldIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The identity provider "https://idp.acme.example/saml": the attribute "mail" fills the claim "email", which the profile of a person does not hold in this deployment (spec/saml.md S-45).');

        // When
        new ConfigurationUpstreamIdentityProviders(
            'acme',
            ['https://idp.acme.example/saml' => [...self::declaration(['acme.example']), 'profile' => ['mail' => 'email']]],
            new FixedProfileClaims(),
        );
    }

    /**
     * Section 6.10 step 1: a declaration that does not hold together is refused, naming the identity provider.
     */
    #[Test]
    #[DataProvider('provideDeclarationsThatDoNotHoldTogether')]
    public function aDeclarationThatDoesNotHoldTogetherIsRefused(mixed $declaration, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The identity provider "https://idp.acme.example/saml": ' . $message);

        // When
        new ConfigurationUpstreamIdentityProviders('acme', ['https://idp.acme.example/saml' => $declaration], new FixedProfileClaims());
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideDeclarationsThatDoNotHoldTogether(): iterable
    {
        yield 'not a map' => ['https://idp.acme.example/saml/metadata', 'a declaration is a map (spec/saml.md section 5.7).'];
        yield 'no metadata' => [['domains' => ['acme.example'], 'email_attribute' => 'mail'], '"metadata" is a string.'];
        yield 'no attribute of the e-mail' => [['metadata' => '/srv/saml/idp.xml', 'domains' => ['acme.example']], '"email_attribute" is a string.'];
        yield 'a domain that is none' => [
            self::declaration(['localhost']),
            '"localhost" is no e-mail domain: a name of the DNS of two labels at least, of letters, digits and hyphens, a name outside ASCII written as its A-label.',
        ];
        yield 'groups that are no map' => [[...self::declaration(['acme.example']), 'groups' => 'groups'], '"groups" is a map (spec/saml.md section 5.7).'];
        yield 'groups without their attribute' => [
            [...self::declaration(['acme.example']), 'groups' => ['map' => ['member' => 'Members']]],
            '"attribute" is a string.',
        ];
        yield 'a group that is no string' => [
            [...self::declaration(['acme.example']), 'groups' => ['attribute' => 'groups', 'map' => ['member' => ['Members']]]],
            '"map" is a string.',
        ];
        yield 'a subject that is no string' => [[...self::declaration(['acme.example']), 'subject_attribute' => ['oid']], '"subject_attribute" is a string.'];
        yield 'a requirement of encryption that is no boolean' => [
            [...self::declaration(['acme.example']), 'require_encrypted_assertions' => 'yes'],
            '"require_encrypted_assertions" is a boolean.',
        ];
        yield 'a parameter of the address that is no string' => [
            [...self::declaration(['acme.example']), 'address_parameter' => ['login_hint']],
            '"address_parameter" is a string.',
        ];
        yield 'a parameter of the address that is no token' => [
            [...self::declaration(['acme.example']), 'address_parameter' => 'login hint'],
            'The parameter of the address is one to 64 unreserved characters of RFC 3986 (spec/saml.md S-68).',
        ];
        yield 'a parameter of the address the binding holds' => [
            [...self::declaration(['acme.example']), 'address_parameter' => 'Signature'],
            'The parameter of the address "Signature" is a parameter of the binding (spec/saml.md S-68).',
        ];
    }

    /**
     * S-67: whether the assertions of an identity provider must arrive encrypted is read from its declaration, and
     * they need not unless it says so.
     *
     * @param array<string, mixed> $declared
     */
    #[Test]
    #[DataProvider('provideRequirementsOfEncryption')]
    public function whetherAssertionsMustArriveEncryptedIsRead(array $declared, bool $required): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            ['https://idp.acme.example/saml' => [...self::declaration(['acme.example']), ...$declared]],
            new FixedProfileClaims(),
        );

        // When
        $identityProvider = $identityProviders->find(
            Fixtures::tenant('acme'),
            'https://idp.acme.example/saml',
        ) ?? static::fail('The identity provider is not declared.');

        // Then
        static::assertSame($required, $identityProvider->requireEncryptedAssertions);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function provideRequirementsOfEncryption(): iterable
    {
        yield 'not declared' => [[], false];
        yield 'declared false' => [['require_encrypted_assertions' => false], false];
        yield 'declared true' => [['require_encrypted_assertions' => true], true];
    }

    /**
     * S-68: the parameter of the address of an identity provider is read from its declaration, and there is none unless
     * it names one.
     *
     * @param array<string, mixed> $declared
     */
    #[Test]
    #[DataProvider('provideParametersOfTheAddress')]
    public function theParameterOfTheAddressIsRead(array $declared, ?string $parameter): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            ['https://idp.acme.example/saml' => [...self::declaration(['acme.example']), ...$declared]],
            new FixedProfileClaims(),
        );

        // When
        $identityProvider = $identityProviders->find(
            Fixtures::tenant('acme'),
            'https://idp.acme.example/saml',
        ) ?? static::fail('The identity provider is not declared.');

        // Then
        static::assertSame($parameter, $identityProvider->addressParameter);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, ?string}>
     */
    public static function provideParametersOfTheAddress(): iterable
    {
        yield 'not declared' => [[], null];
        yield 'declared null' => [['address_parameter' => null], null];
        yield 'declared' => [['address_parameter' => 'login_hint'], 'login_hint'];
    }

    /**
     * S-42, M-6: a declaration under an entity ID that is no URI as the model reads one is refused, naming the rule.
     */
    #[Test]
    public function aDeclarationUnderAnEntityIdThatIsNoUriIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The identity provider "idp.acme.example": The entity ID of an identity provider is refused (spec/saml.md S-42): A URI is not absolute (M-6).');

        // When
        new ConfigurationUpstreamIdentityProviders('acme', ['idp.acme.example' => self::declaration(['acme.example'])], new FixedProfileClaims());
    }

    /**
     * The declarations are those of one tenant, named by its slug: another tenant has none.
     */
    #[Test]
    public function anotherTenantDeclaresNone(): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            ['https://idp.acme.example/saml' => self::declaration(['acme.example'])],
            new FixedProfileClaims(),
        );

        // When / Then
        static::assertSame([], $identityProviders->of(Fixtures::tenant('other')));
    }

    /**
     * The declarations are those of one tenant: another tenant finds none of them.
     */
    #[Test]
    public function anotherTenantFindsNone(): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            ['https://idp.acme.example/saml' => self::declaration(['acme.example'])],
            new FixedProfileClaims(),
        );

        // When / Then
        static::assertNull($identityProviders->find(Fixtures::tenant('other'), 'https://idp.acme.example/saml'));
    }

    /**
     * An entity ID nobody declared is found nowhere.
     */
    #[Test]
    public function anEntityIdNobodyDeclaredIsNotFound(): void
    {
        // Given
        $identityProviders = new ConfigurationUpstreamIdentityProviders(
            'acme',
            ['https://idp.acme.example/saml' => self::declaration(['acme.example'])],
            new FixedProfileClaims(),
        );

        // When / Then
        static::assertNull($identityProviders->find(Fixtures::tenant('acme'), 'https://idp.acme.example/saml/'));
    }

    /**
     * @param list<string> $domains
     *
     * @return array<string, mixed>
     */
    private static function declaration(array $domains): array
    {
        return [
            'metadata' => '/srv/saml/idp.xml',
            'domains' => $domains,
            'email_attribute' => 'mail',
        ];
    }
}
