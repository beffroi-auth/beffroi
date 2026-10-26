<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\Type;

use DateTimeImmutable;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Types\ConversionException;
use Doctrine\DBAL\Types\Type;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2i;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Bundle\Doctrine\Type\PasswordAlgorithmType;
use Beffroi\Bundle\Doctrine\Type\ActorType;
use Beffroi\Bundle\Doctrine\Type\AddressType;
use Beffroi\Bundle\Doctrine\Type\AuthenticationContextPolicyType;
use Beffroi\Bundle\Doctrine\Type\AuthenticationPredicateType;
use Beffroi\Bundle\Doctrine\Type\AuthenticationProofsType;
use Beffroi\Bundle\Doctrine\Type\BackupCodesType;
use Beffroi\Bundle\Doctrine\Type\ClaimsRequestType;
use Beffroi\Bundle\Doctrine\Type\ClientSecretType;
use Beffroi\Bundle\Doctrine\Type\CodeChallengeType;
use Beffroi\Bundle\Doctrine\Type\DeviceType;
use Beffroi\Bundle\Doctrine\Type\EmailAddressType;
use Beffroi\Bundle\Doctrine\Type\GeoLocationType;
use Beffroi\Bundle\Doctrine\Type\IssuerType;
use Beffroi\Bundle\Doctrine\Type\PasskeyUserHandleType;
use Beffroi\Bundle\Doctrine\Type\RedirectUriType;
use Beffroi\Bundle\Doctrine\Type\AuthorizationDetailsType;
use Beffroi\Bundle\Doctrine\Type\ResourceIndicatorsType;
use Beffroi\Bundle\Doctrine\Type\ScopesType;
use Beffroi\Bundle\Doctrine\Type\SubjectType;
use Beffroi\Bundle\Doctrine\Type\SelfServedClaimsType;
use Beffroi\Bundle\Doctrine\Type\UserSourceType;
use Beffroi\Bundle\Doctrine\Type\TenantLookType;
use Beffroi\Bundle\Doctrine\Type\LogoutProgressType;
use Beffroi\Saml\Domain\SingleLogout\LogoutHop;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\LogoutRequester;
use Symfony\Component\Uid\Uuid;
use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Bundle\BeffroiBundle;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Core\Tests\Fixture\Predicates;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType as DeviceKind;
use Beffroi\Core\Domain\Session\GeoLocation;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

/**
 * Architecture §5.3: every value object a column holds as one value goes to the database and comes back
 * equal, byte for byte what the column holds today, and what the database holds that is not such a value
 * is a conversion error, never a guess.
 *
 * **It judges the Doctrine half.** What the document of a value looks like, and which document is refused
 * member by member, is tested with the object that writes it, in the suite of the package that owns it,
 * with nothing booted (issue #603); here, one refusal per type says that what that object refuses reaches
 * a caller of Doctrine as a `ConversionException`.
 */
final class TypesTest extends TestCase
{
    /**
     * The types that read a wiring back are told what the deployment is wired with, as the bundle tells
     * them when it boots; without a kernel here, the test is the deployment.
     */
    public static function setUpBeforeClass(): void
    {
        $algorithms = new WiredPasswordAlgorithms([
            new Argon2id(),
            new Argon2i(),
            new Bcrypt(),
            new Pbkdf2Sha256(),
            new Pbkdf2Sha512(),
        ]);
        PasswordAlgorithmType::resolveWith($algorithms);
        ClientSecretType::resolveWith($algorithms);
        BackupCodesType::resolveWith($algorithms);
        AuthorizationDetailsType::resolveWith(AuthorizationDetailTypes::served());
        CodeChallengeType::resolveWith(ChallengeMethods::s256());
        AuthenticationContextPolicyType::resolveWith(Predicates::wired());
        AuthenticationPredicateType::resolveWith(Predicates::wired());
    }

    /**
     * @return iterable<string, array{class-string<Type>, object|list<Scope>|list<BackupCode>, string}>
     */
    public static function provideValues(): iterable
    {
        yield 'issuer' => [IssuerType::class, new Issuer('https://op.example/tenant'), 'https://op.example/tenant'];
        yield 'subject' => [SubjectType::class, new Subject('alice-subject'), 'alice-subject'];
        yield 'password algorithm' => [PasswordAlgorithmType::class, new Argon2id(), 'argon2id'];
        yield 'email address' => [EmailAddressType::class, new EmailAddress('alice@example.com'), 'alice@example.com'];
        yield 'redirect URI' => [
            RedirectUriType::class,
            new RedirectUri('https://demo.example/login/check?dummy=1'),
            'https://demo.example/login/check?dummy=1',
        ];
        yield 'code challenge' => [
            CodeChallengeType::class,
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', new Sha256CodeChallengeMethod()),
            'S256:E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        ];
        yield 'scopes' => [ScopesType::class, new Scopes([new Scope('openid'), new Scope('profile')]), 'openid profile'];
        yield 'resources' => [
            ResourceIndicatorsType::class,
            ResourceIndicators::of(['https://cal.example.com/', 'https://contacts.example.com/']),
            'https://cal.example.com/ https://contacts.example.com/',
        ];
        yield 'authorization details' => [
            AuthorizationDetailsType::class,
            AuthorizationDetailTypes::details('acct-4711', ['read', 'write']),
            '[{"type":"account_information","account":"acct-4711","actions":["read","write"]}]',
        ];
        yield 'proofs' => [
            AuthenticationProofsType::class,
            AuthenticationProofs::of(AuthenticationMethod::password(), new DateTimeImmutable('@1789000000'))->with(
                new AuthenticationMethod('otp'),
                new DateTimeImmutable('@1789000060'),
            ),
            '{"pwd":1789000000,"otp":1789000060}',
        ];
        yield 'location' => [
            GeoLocationType::class,
            new GeoLocation('FR', 'Île-de-France', 'Paris', 3215, 'Orange S.A.', 48.8566, 2.3522),
            '{"country_code":"FR","region":"Île-de-France","city":"Paris","asn":3215,"as_organization":"Orange S.A.","latitude":48.8566,"longitude":2.3522}',
        ];
        yield 'empty location' => [
            GeoLocationType::class,
            new GeoLocation(),
            '{"country_code":null,"region":null,"city":null,"asn":null,"as_organization":null,"latitude":null,"longitude":null}',
        ];
        yield 'device' => [
            DeviceType::class,
            new Device(DeviceKind::Desktop, 'Firefox', '140.0', 'Linux'),
            '{"type":"desktop","browser":"Firefox","browser_version":"140.0","platform":"Linux","platform_version":null}',
        ];
        yield 'address' => [
            AddressType::class,
            new Address('1 rue de la Paix, 75002 Paris', '1 rue de la Paix', 'Paris', null, '75002', 'FR'),
            '{"formatted":"1 rue de la Paix, 75002 Paris","street_address":"1 rue de la Paix","locality":"Paris","region":null,"postal_code":"75002","country":"FR"}',
        ];
        yield 'claims request' => [
            ClaimsRequestType::class,
            new ClaimsRequest([
                'email' => new ClaimRequest(true),
                'name' => new ClaimRequest(),
            ], [
                'acr' => new ClaimRequest(false, null, ['silver', 'gold']),
                'auth_time' => new ClaimRequest(true, 1789000000),
            ]),
            '{"userinfo":{"email":{"essential":true},"name":null},"id_token":{"acr":{"values":["silver","gold"]},"auth_time":{"essential":true,"value":1789000000}}}',
        ];
        yield 'claims request asking for nothing' => [ClaimsRequestType::class, new ClaimsRequest(), '{"userinfo":{},"id_token":{}}'];
        yield 'passkey user handle' => [PasskeyUserHandleType::class, new PasskeyUserHandle(str_repeat("\xff", 64)), str_repeat('_', 85) . 'w'];
        yield 'authentication context policy' => [
            AuthenticationContextPolicyType::class,
            new AuthenticationContextPolicy([
                new AuthenticationContextClass('urn:okta:loa:2fa:any', new TwoFactors()),
                AuthenticationContextClass::singleFactor(),
            ]),
            '{"classes":[{"name":"urn:okta:loa:2fa:any","predicate":"two_factors"},{"name":"1","predicate":"single_factor"}]}',
        ];
        yield 'the floor of the logins of a tenant' => [AuthenticationPredicateType::class, new PhishingResistant(), 'phishing_resistant'];
        yield 'the floor of a tenant that hardened nothing' => [AuthenticationPredicateType::class, new SingleFactor(), 'single_factor'];
        yield 'what a person may change of themselves' => [
            SelfServedClaimsType::class,
            new SelfServedClaims(['nickname', 'zoneinfo']),
            '["nickname","zoneinfo"]',
        ];
        yield 'a tenant that lets a person change nothing' => [SelfServedClaimsType::class, SelfServedClaims::none(), '[]'];
        yield 'the look of a tenant' => [
            TenantLookType::class,
            new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff'),
            '{"logo_uri":"https://acme.example/logo.svg","primary_color":"#1b4b8f","primary_content_color":"#ffffff"}',
        ];
        // a tenant that declared nothing is an empty document and not three nulls (issue #449), which PHP
        // writes as a JSON array; the default of the column is "{}" and both read back as the same look
        yield 'the look of a tenant that declared none' => [TenantLookType::class, TenantLook::none(), '[]'];
        yield 'backup codes' => [
            BackupCodesType::class,
            [new BackupCode(new PasswordHash(new Argon2id(), '$argon2id$one')), new BackupCode(new PasswordHash(
                    new Pbkdf2Sha256(),
                    'two',
                    [
                        'salt' => 'c2FsdA',
                        'iterations' => 27500,
                    ],
                ), new DateTimeImmutable('@1789000060'))],
            '[{"algorithm":"argon2id","encoded":"$argon2id$one","parameters":[],"used_at":null},{"algorithm":"pbkdf2-sha256","encoded":"two","parameters":{"salt":"c2FsdA","iterations":27500},"used_at":1789000060}]',
        ];
        yield 'no backup code' => [BackupCodesType::class, [], '[]'];
        yield 'the secret of a client that presents it' => [
            ClientSecretType::class,
            new HashedClientSecret(new PasswordHash(new Argon2id(), '$argon2id$the-secret-of-a-client')),
            '{"hash":{"algorithm":"argon2id","encoded":"$argon2id$the-secret-of-a-client","parameters":[]}}',
        ];
        yield 'the secret of a client that signs with it' => [
            ClientSecretType::class,
            new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3'),
            '{"shared":"a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3"}',
        ];
        yield 'one actor' => [ActorType::class, new Actor(new Subject('gateway')), '{"sub":"gateway"}'];
        yield 'a chain of SAML logout a service provider started' => [
            LogoutProgressType::class,
            new LogoutProgress(
                [Uuid::fromString('0199e8a4-6f00-7000-8000-000000000001')],
                [new LogoutHop(Uuid::fromString('0199e8a4-6f00-7000-8000-000000000001'), 'https://sp.example.org/saml')],
                'https://other.example.org/saml',
                true,
                new LogoutRequester(
                    'https://asked.example.org/saml',
                    '_9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b',
                    'state-1',
                    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    'https://asked.example.org/saml/slo',
                ),
                null,
            ),
            '{"sessions":["0199e8a4-6f00-7000-8000-000000000001"],"hops":[{"session":"0199e8a4-6f00-7000-8000-000000000001","service_provider":"https://sp.example.org/saml"}],"awaiting_from":"https://other.example.org/saml","partial":true,"requester":{"service_provider":"https://asked.example.org/saml","request_id":"_9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b","relay_state":"state-1","answer_binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect","answer_location":"https://asked.example.org/saml/slo"},"continue_to":null}',
        ];
        yield 'a chain of actors' => [
            ActorType::class,
            new Actor(new Subject('backend'), new Actor(new Subject('gateway'))),
            '{"sub":"backend","act":{"sub":"gateway"}}',
        ];
    }

    /**
     * @param class-string<Type> $type
     * @param object|list<Scope>|list<BackupCode> $value
     */
    #[Test]
    #[DataProvider('provideValues')]
    public function aValueGoesToTheDatabaseAsOneValue(string $type, object|array $value, string $stored): void
    {
        // Given
        $type = self::type($type);

        // When
        $written = $type->convertToDatabaseValue($value, new SQLitePlatform());

        // Then
        static::assertSame($stored, $written);
    }

    /**
     * @param class-string<Type> $type
     * @param object|list<Scope>|list<BackupCode> $value
     */
    #[Test]
    #[DataProvider('provideValues')]
    public function aValueComesBackEqual(string $type, object|array $value, string $stored): void
    {
        // Given
        $type = self::type($type);

        // When
        $read = $type->convertToPHPValue($stored, new SQLitePlatform());

        // Then
        static::assertEquals($value, $read);
    }

    /**
     * @param class-string<Type> $type
     * @param object|list<Scope>|list<BackupCode> $value
     */
    #[Test]
    #[DataProvider('provideValues')]
    public function nullGoesBothWaysAsNull(string $type, object|array $value, string $stored): void
    {
        // Given
        $platform = new SQLitePlatform();
        $type = self::type($type);

        // When / Then
        static::assertNull($type->convertToDatabaseValue(null, $platform));
        static::assertNull($type->convertToPHPValue(null, $platform));
    }

    /**
     * @return iterable<string, array{class-string<Type>, mixed}>
     */
    public static function provideValuesThatAreNotStorable(): iterable
    {
        yield 'a string for an issuer' => [IssuerType::class, 'https://op.example'];
        yield 'a subject for an issuer' => [IssuerType::class, new Subject('alice')];
        yield 'a list of strings for scopes' => [ScopesType::class, ['openid']];
        yield 'a list of strings for resources' => [ResourceIndicatorsType::class, ['https://cal.example.com/']];
        yield 'a string for scopes' => [ScopesType::class, 'openid'];
        yield 'an array for proofs' => [
            AuthenticationProofsType::class,
            [
                'pwd' => 1,
            ],
        ];
        yield 'a string for a claims request' => [ClaimsRequestType::class, '{}'];
        yield 'a subject for an actor' => [ActorType::class, new Subject('gateway')];
        yield 'a string for a user handle' => [PasskeyUserHandleType::class, str_repeat('h', 64)];
        yield 'an array for a policy' => [
            AuthenticationContextPolicyType::class,
            [
                '1' => 'single_factor',
            ],
        ];
        yield 'a name for a predicate' => [AuthenticationPredicateType::class, 'single_factor'];
        yield 'a string for backup codes' => [BackupCodesType::class, 'K7Q2M-X9PL4'];
        yield 'a list of strings for backup codes' => [BackupCodesType::class, ['K7Q2M-X9PL4']];
        yield 'a string for authorization details' => [AuthorizationDetailsType::class, '[]'];
        yield 'a detail alone for authorization details' => [AuthorizationDetailsType::class, AuthorizationDetailTypes::detail()];
        yield 'a string for the progress of a chain' => [LogoutProgressType::class, '{}'];
        yield 'a name for the source of a person' => [UserSourceType::class, 'local'];
    }

    /**
     * @param class-string<Type> $type
     */
    #[Test]
    #[DataProvider('provideValuesThatAreNotStorable')]
    public function whatIsNotTheValueObjectIsNotStored(string $type, mixed $value): void
    {
        // Given
        $type = self::type($type);

        // Then
        $this->expectException(ConversionException::class);

        // When
        $type->convertToDatabaseValue($value, new SQLitePlatform());
    }

    /**
     * @return iterable<string, array{class-string<Type>, mixed}>
     */
    public static function provideStoredValuesThatAreNotReadable(): iterable
    {
        yield 'an issuer with a fragment' => [IssuerType::class, 'https://op.example/#x'];
        yield 'an issuer that is not a string' => [IssuerType::class, 12];
        yield 'a subject with a space' => [SubjectType::class, 'alice example'];
        yield 'a password algorithm nothing accounts for' => [PasswordAlgorithmType::class, 'scrypt'];
        yield 'a malformed email address' => [EmailAddressType::class, 'alice'];
        yield 'a redirect URI in plain HTTP' => [RedirectUriType::class, 'http://demo.example/login/check'];
        yield 'a code challenge without a method' => [CodeChallengeType::class, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'];
        yield 'a scope with a quote' => [ScopesType::class, 'open"id'];
        yield 'a resource that is not an absolute URI' => [ResourceIndicatorsType::class, 'cal.example.com'];
        yield 'a resource with a fragment' => [ResourceIndicatorsType::class, 'https://cal.example.com/#today'];
        yield 'resources that are not a string' => [ResourceIndicatorsType::class, ['https://cal.example.com/']];
        yield 'scopes that are not a string' => [ScopesType::class, ['openid']];
        yield 'proofs that are not JSON' => [AuthenticationProofsType::class, '{'];
        yield 'proofs that are a JSON list' => [AuthenticationProofsType::class, '[1]'];
        yield 'an actor with no subject' => [ActorType::class, '{"client_id":"gateway"}'];
        yield 'an actor that is a JSON list' => [ActorType::class, '["gateway"]'];
        yield 'an actor whose nested one is not an object' => [ActorType::class, '{"sub":"backend","act":"gateway"}'];
        yield 'authorization details that are not JSON' => [AuthorizationDetailsType::class, '['];
        yield 'authorization details that are a JSON object' => [AuthorizationDetailsType::class, '{"type":"account_information"}'];
        yield 'authorization details naming no type' => [AuthorizationDetailsType::class, '[{"account":"acct-4711"}]'];
        yield 'authorization details of a type nobody serves' => [
            AuthorizationDetailsType::class,
            '[{"type":"payment_initiation","account":"acct-4711"}]',
        ];
        yield 'authorization details the type refuses' => [AuthorizationDetailsType::class, '[{"type":"account_information"}]'];
        yield 'a location with a bad country code' => [GeoLocationType::class, '{"country_code":"France"}'];
        yield 'a device without a type' => [DeviceType::class, '{"browser":"Firefox"}'];
        yield 'an address with a numeric postal code' => [AddressType::class, '{"postal_code":75002}'];
        yield 'a claims request that is a list' => [ClaimsRequestType::class, '[1]'];
        yield 'a claims request that is not a string' => [ClaimsRequestType::class, 12];
        yield 'a user handle that is not base64url' => [PasskeyUserHandleType::class, str_repeat('*', 86)];
        yield 'a policy that is a list' => [AuthenticationContextPolicyType::class, '[1]'];
        yield 'a policy with a predicate the provider does not define' => [
            AuthenticationContextPolicyType::class,
            '{"classes":[{"name":"1","predicate":"attested"}]}',
        ];
        yield 'a floor the provider does not define' => [AuthenticationPredicateType::class, 'attested'];
        yield 'backup codes that are not JSON' => [BackupCodesType::class, '['];
        yield 'backup codes that are not a list' => [BackupCodesType::class, '12'];
        yield 'a backup code without an algorithm' => [BackupCodesType::class, '[{"encoded":"x","parameters":[],"used_at":null}]'];
        yield 'backup codes that are not a string' => [BackupCodesType::class, 12];
        yield 'the progress of a chain whose session is no UUID' => [LogoutProgressType::class, '{"sessions":["session-1"],"partial":false}'];
        yield 'the progress of a chain that does not say whether it is partial' => [LogoutProgressType::class, '{"sessions":[]}'];
        yield 'the source of a person that names no provider' => [UserSourceType::class, '{"claims":["email"]}'];
        yield 'the source of a person whose claims are not names' => [UserSourceType::class, '{"provider":"workforce","claims":[12]}'];
    }

    /**
     * @param class-string<Type> $type
     */
    #[Test]
    #[DataProvider('provideStoredValuesThatAreNotReadable')]
    public function whatTheDatabaseHoldsThatIsNotTheValueObjectIsNotRead(string $type, mixed $stored): void
    {
        // Given
        $type = self::type($type);

        // Then
        $this->expectException(ConversionException::class);

        // When
        $type->convertToPHPValue($stored, new SQLitePlatform());
    }

    #[Test]
    public function anEmptyScopeStringReadsAsNoScopeAtAll(): void
    {
        // When / Then
        static::assertNull(self::type(ScopesType::class)->convertToPHPValue('', new SQLitePlatform()));
    }

    /**
     * The JSON documents are JSONB on PostgreSQL when the mapping asks, JSON otherwise; a string is a
     * string everywhere.
     *
     * @param class-string<Type> $type
     * @param array<string, mixed> $column
     */
    #[Test]
    #[DataProvider('provideColumnDeclarations')]
    public function theColumnsDeclareThemselvesForEachPlatform(string $type, array $column, AbstractPlatform $platform, string $declaration): void
    {
        // When / Then
        static::assertSame($declaration, self::type($type)->getSQLDeclaration($column, $platform));
    }

    /**
     * @return iterable<string, array{class-string<Type>, array<string, mixed>, AbstractPlatform, string}>
     */
    public static function provideColumnDeclarations(): iterable
    {
        yield 'JSONB on PostgreSQL when asked' => [
            GeoLocationType::class,
            [
                'jsonb' => true,
            ],
            new PostgreSQLPlatform(),
            'JSONB',
        ];
        yield 'JSON on PostgreSQL otherwise' => [AddressType::class, [], new PostgreSQLPlatform(), 'JSON'];
        yield 'CLOB on SQLite' => [ClaimsRequestType::class, [], new SQLitePlatform(), 'CLOB'];
        yield 'a string with a length' => [
            IssuerType::class,
            [
                'length' => 255,
            ],
            new PostgreSQLPlatform(),
            'VARCHAR(255)',
        ];
        yield 'a string without a length' => [ScopesType::class, [], new PostgreSQLPlatform(), 'TEXT'];
    }

    /**
     * The bundle declares every type to Doctrine under the name the mappings use.
     *
     * @param class-string<Type> $class
     */
    #[Test]
    #[DataProvider('provideDeclaredTypes')]
    public function everyTypeIsDeclaredUnderItsName(string $name, string $class): void
    {
        // When / Then
        static::assertSame($class::NAME, $name);
        static::assertInstanceOf($class, self::type($class));
    }

    /**
     * @return iterable<string, array{string, class-string<Type>}>
     */
    public static function provideDeclaredTypes(): iterable
    {
        foreach (BeffroiBundle::DBAL_TYPES as $name => $class) {
            yield $name => [$name, $class];
        }
    }

    #[Test]
    public function theBundleDeclaresThirtyThreeTypes(): void
    {
        // When / Then
        static::assertCount(33, BeffroiBundle::DBAL_TYPES);
    }

    /**
     * @param class-string<Type> $class
     */
    private static function type(string $class): Type
    {
        $name = $class::NAME;
        static::assertIsString($name);
        if (! Type::hasType($name)) {
            Type::addType($name, $class);
        }
        $type = Type::getType($name);
        static::assertInstanceOf($class, $type, sprintf('"%s" is registered as another type.', $name));

        return $type;
    }
}
