<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use function explode;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\TenantKeyRotated;
use Beffroi\Core\Domain\Event\TenantKeyStaged;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Port\SigningKeyProviderInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_repeat;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;

/**
 * Architecture §5.5: a fresh application is provisioned from the console only, the tenant first, then a
 * key and a user; nothing else writes before the first login.
 */
final class ProvisioningTest extends ConsoleTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * The acceptance criterion of the commands, step 1: after a migration, the tenant of the
     * configuration becomes a row.
     */
    #[Test]
    public function theTenantOfTheConfigurationIsSynchronisedAsARow(): void
    {
        // Given
        self::dropTenant();

        // When
        $tester = self::console('beffroi:tenant:synchronize');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('https://op.test', $tester->getDisplay());
        static::assertStringContainsString('The tenant "default" is synchronised', $tester->getDisplay());
        // what the pages show of it is written with the rest of the row, so the command says it (issue #449);
        // this deployment declares none, and the two lines are empty rather than absent
        static::assertStringContainsString('Logo', $tester->getDisplay());
        static::assertStringContainsString('Colours', $tester->getDisplay());
        // and what its people may change of themselves (issue #452), which the same command writes
        static::assertStringContainsString('Changeable', $tester->getDisplay());
    }

    /**
     * Step 4: the JWK Set publishes the key the console generated.
     */
    #[Test]
    public function theJwkSetPublishesTheKeyOfTheConsole(): void
    {
        // Given
        $kid = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        $jwks = self::json($this->browser->getResponse());
        static::assertIsArray($jwks['keys']);
        static::assertCount(1, $jwks['keys']);
        static::assertIsArray($jwks['keys'][0]);
        static::assertSame($kid, $jwks['keys'][0]['kid']);
        static::assertArrayNotHasKey('d', $jwks['keys'][0]);
    }

    /**
     * Step 3: the password typed twice on the terminal is never echoed.
     */
    #[Test]
    public function thePasswordTypedOnTheTerminalIsNeverEchoed(): void
    {
        // Given
        self::console('beffroi:user:create', [
            'username' => 'alice',
        ]);

        // When
        $tester = self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
            ],
            [self::PASSWORD, self::PASSWORD],
        );

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringNotContainsString('correct horse', $tester->getDisplay());
    }

    /**
     * Step 5: the user signs in on the form with the password of the console.
     */
    #[Test]
    public function theUserOfTheConsoleSignsInOnTheForm(): void
    {
        // Given
        self::provisionAliceFromTheConsole();
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $form = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ])->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;

        // When
        $this->browser->submit($form);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        static::assertSame('/consent?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * Step 5: the flow of OIDC Core §3.1 runs on what the console wrote; the ID token is signed with the
     * key of the console and its "sub" is the subject the console printed.
     */
    #[Test]
    public function theIdTokenIsSignedWithTheKeyOfTheConsoleForTheSubjectItPrinted(): void
    {
        // Given
        ['kid' => $kid, 'subject' => $subject] = self::provisionAliceFromTheConsole();
        $code = $this->codeOfAliceSignedInOnTheForm();

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $idToken = explode('.', self::string(self::json($response)['id_token']));
        $header = json_decode(self::base64UrlDecode($idToken[0]), true, 4, JSON_THROW_ON_ERROR);
        static::assertIsArray($header);
        static::assertSame($kid, $header['kid']);
        $claims = json_decode(self::base64UrlDecode($idToken[1]), true, 4, JSON_THROW_ON_ERROR);
        static::assertIsArray($claims);
        static::assertSame($subject, $claims['sub']);
    }

    #[Test]
    public function theTenantIsSynchronisedOnceAndLeftAloneAfterwards(): void
    {
        // Given
        $tenant = self::tenant();

        // When
        $tester = self::console('beffroi:tenant:synchronize');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($tenant->id->toRfc4122(), self::displayed($tester, 'Identifier'));
        static::assertSame('op.test', self::displayed($tester, 'Name'));
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideCommandsThatNeedTheTenant')]
    public function nothingIsProvisionedBeforeTheTenantIs(string $name, array $input): void
    {
        // Given
        self::dropTenant();

        // When
        $tester = self::console($name, $input, [self::PASSWORD]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('has no row yet', $tester->getDisplay());
        static::assertStringContainsString('beffroi:tenant:synchronize', $tester->getDisplay());
        static::assertSame(0, self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM beffroi_user'));
        static::assertDirectoryDoesNotExist(self::keyStorage());
    }

    /**
     * @return iterable<string, array{string, array<string, string|bool>}>
     */
    public static function provideCommandsThatNeedTheTenant(): iterable
    {
        yield 'beffroi:keys:generate' => ['beffroi:keys:generate', []];
        yield 'beffroi:keys:rotate' => ['beffroi:keys:rotate', []];
        yield 'beffroi:keys:activate' => [
            'beffroi:keys:activate',
            [
                'kid' => 'nope',
            ],
        ];
        yield 'beffroi:keys:retire' => [
            'beffroi:keys:retire',
            [
                '--due' => true,
            ],
        ];
        yield 'beffroi:keys:list' => ['beffroi:keys:list', []];
        yield 'beffroi:user:create' => [
            'beffroi:user:create',
            [
                'username' => 'alice',
            ],
        ];
        yield 'beffroi:user:profile' => [
            'beffroi:user:profile',
            [
                'username' => 'alice',
                '--name' => 'Alice Liddell',
            ],
        ];
        yield 'beffroi:user:show' => [
            'beffroi:user:show',
            [
                'username' => 'alice',
            ],
        ];
        yield 'beffroi:user:set-password' => [
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
        ];
    }

    /**
     * Architecture §3.3: a generated key is active and said so.
     */
    #[Test]
    public function aGeneratedKeyIsActive(): void
    {
        // When
        $tester = self::console('beffroi:keys:generate');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $kid = self::displayed($tester, 'Key identifier');
        static::assertSame('RS256', self::displayed($tester, 'Algorithm'));
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringNotContainsString('is now retiring', $tester->getDisplay());
        $key = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->find(self::tenant(), $kid) ?? static::fail('The key is not stored.');
        static::assertTrue($key->isActive());
        static::assertSame(
            $kid,
            self::service('test.beffroi.key_provider', SigningKeyProviderInterface::class)->activeKey(self::tenant(), Algorithms::rs256())->key->kid,
        );
    }

    /**
     * Issue #164: what "castor provision" runs to give the tenant the other half of its JWK Set, a key a
     * client encrypts to. The same command, the same custody, "use": "enc".
     */
    #[Test]
    public function aGeneratedEncryptionKeyIsActiveAndPublishedForEncryption(): void
    {
        // When
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => 'ECDH-ES+A256KW',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $key = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)
            ->find(self::tenant(), self::displayed($tester, 'Key identifier')) ?? static::fail('The key is not stored.');
        static::assertSame('ECDH-ES+A256KW', self::displayed($tester, 'Algorithm'));
        static::assertSame('enc', self::displayed($tester, 'Use'));
        static::assertTrue($key->isActive());
        static::assertSame('enc', $key->publicJwk['use']);
    }

    /**
     * Architecture §3.3: the private key is sealed before it is written, never in clear.
     */
    #[Test]
    public function aGeneratedKeyIsSealedBeforeItIsWritten(): void
    {
        // When
        $kid = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');

        // Then
        static::assertStringNotContainsString('"d"', self::string(file_get_contents(self::keyStorage() . '/default/' . $kid . '.json')));
    }

    /**
     * Architecture §3.3: the key is staged then activated at once, both announced, with the context of a
     * console that names its command and the user of the shell, and has no address.
     */
    #[Test]
    public function aGeneratedKeyIsAnnounced(): void
    {
        // When
        $kid = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');

        // Then
        $events = self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events;
        static::assertCount(2, $events);
        static::assertInstanceOf(TenantKeyStaged::class, $events[0]);
        static::assertSame($kid, $events[0]->staged->kid);
        static::assertInstanceOf(TenantKeyRotated::class, $events[1]);
        static::assertSame($kid, $events[1]->activated->kid);
        static::assertNull($events[1]->retiring);
        static::assertNull($events[1]->context->ipAddress);
        static::assertStringStartsWith('beffroi-console/beffroi:keys:generate (', $events[1]->context->userAgent ?? '');
    }

    #[Test]
    public function theListSaysWhenThereIsNoPublishedKey(): void
    {
        // When
        $tester = self::console('beffroi:keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('has no published key', $tester->getDisplay());
    }

    #[Test]
    public function generatingASecondKeyIsARotation(): void
    {
        // Given
        $first = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:generate');

        // Then
        $second = self::displayed($tester, 'Key identifier');
        static::assertNotSame($first, $second);
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $first), self::flattened($tester));
        $keys = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class);
        static::assertSame(KeyStatus::Retiring, $keys->find(self::tenant(), $first)?->status);
        static::assertSame(KeyStatus::Active, $keys->find(self::tenant(), $second)?->status);
    }

    #[Test]
    public function theListShowsThePublishedKeysWithTheirStatusAndDates(): void
    {
        // Given
        $first = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');
        $second = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');

        // When
        $tester = self::console('beffroi:keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertMatchesRegularExpression(
            sprintf(
                '/Key identifier\s+%s\s+Algorithm\s+RS256\s+Use\s+sig\s+Status\s+retiring\s+Created at\s+2026-\S+\s+Activated at\s+2026-\S+\s+Retiring since\s+2026-\S+\s+Retirement due at\s+2026-\S+/',
                $first,
            ),
            self::flattened($tester),
        );
        static::assertMatchesRegularExpression(
            sprintf('/Key identifier\s+%s\s+Algorithm\s+RS256\s+Use\s+sig\s+Status\s+active\s+Created at\s+2026-\S+\s+Activated at\s+2026-\S+\s+-/', $second),
            self::flattened($tester),
        );
    }

    #[Test]
    public function aUserIsCreatedWithAGeneratedSubject(): void
    {
        // When
        $tester = self::console('beffroi:user:create', [
            'username' => ' bob ',
            '--email' => 'bob@example.com',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('bob', self::displayed($tester, 'Username'));
        static::assertSame('bob@example.com (unverified)', self::displayed($tester, 'Email'));
        static::assertInstanceOf(UuidV4::class, Uuid::fromString(self::displayed($tester, 'Subject')));
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findByUsername(self::tenant(), 'bob') ?? static::fail('The user is not stored.');
        static::assertFalse($user->emailVerified);
    }

    #[Test]
    public function aUserIsCreatedWithoutACredential(): void
    {
        // When
        self::console('beffroi:user:create', [
            'username' => 'bob',
        ]);

        // Then
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findByUsername(self::tenant(), 'bob') ?? static::fail('The user is not stored.');
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($user));
    }

    /**
     * Decision 0002: a person the console creates is local, its source holding nothing of it.
     */
    #[Test]
    public function aUserOfTheConsoleIsLocal(): void
    {
        // When
        self::console('beffroi:user:create', [
            'username' => 'bob',
        ]);

        // Then
        self::reload();
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findByUsername(self::tenant(), 'bob') ?? static::fail('The user is not stored.');
        static::assertTrue($user->source->isLocal());
    }

    /**
     * Decision 0002: what the upstream provider that created a person holds, the console does not change,
     * and it says which provider holds it.
     */
    #[Test]
    public function aDescriptionOfAClaimAnUpstreamProviderHoldsIsRefusedNamingIt(): void
    {
        // Given
        $user = User::create(
            Uuid::v7(),
            self::tenant(),
            new Subject('alice-subject'),
            'alice',
            self::now(),
            source: UserSource::upstream('https://idp.acme.example/saml', ['given_name']),
        );
        $user->updateProfile(new Profile(givenName: 'Alice'), self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        // When
        $tester = self::console('beffroi:user:profile', [
            'username' => 'alice',
            '--given-name' => 'Alicia',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The upstream provider "https://idp.acme.example/saml" created this person and holds "given_name"',
            self::flattened($tester),
        );
    }

    /**
     * Decision 0002: an imported identity keeps the subject its clients know.
     */
    #[Test]
    public function anImportedUserKeepsItsSubject(): void
    {
        // When
        $tester = self::console('beffroi:user:create', [
            'username' => 'carol',
            '--subject' => 'carol-from-keycloak',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNotNull(
            self::service('test.beffroi.users', UserRepositoryInterface::class)->findBySubject(self::tenant(), new Subject('carol-from-keycloak')),
        );
    }

    #[Test]
    public function aUsernameIsNotTakenTwice(): void
    {
        // Given
        self::console('beffroi:user:create', [
            'username' => 'carol',
        ]);

        // When
        $tester = self::console('beffroi:user:create', [
            'username' => 'carol',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user named "carol" already exists', $tester->getDisplay());
    }

    #[Test]
    public function aSubjectIsNotTakenTwice(): void
    {
        // Given
        self::console('beffroi:user:create', [
            'username' => 'carol',
            '--subject' => 'carol-from-keycloak',
        ]);

        // When
        $tester = self::console('beffroi:user:create', [
            'username' => 'dave',
            '--subject' => 'carol-from-keycloak',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user with the subject "carol-from-keycloak" already exists', $tester->getDisplay());
        static::assertNull(self::service('test.beffroi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'dave'));
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideInvalidUserOptions')]
    public function whatIsNotAnEmailOrASubjectIsRefusedBeforeAnythingIsWritten(array $input, string $message): void
    {
        // When
        $tester = self::console('beffroi:user:create', [
            'username' => 'erin',
        ] + $input);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString($message, $tester->getDisplay());
        static::assertNull(self::service('test.beffroi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'erin'));
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, string}>
     */
    public static function provideInvalidUserOptions(): iterable
    {
        yield 'not an email address' => [
            [
                '--email' => 'not an address',
            ],
            'is not a valid email address',
        ];
        yield 'not a subject' => [
            [
                '--subject' => 'with a space',
            ],
            'printable ASCII',
        ];
    }

    /**
     * OIDC Core §5.1: the attributes of the "profile", "phone" and "address" scopes, under the names of the
     * specification, on an existing user.
     */
    #[Test]
    public function aUserIsDescribedWithTheStandardClaims(): void
    {
        // Given
        $user = self::user('alice');

        // When
        $tester = self::console('beffroi:user:profile', [
            'username' => ' alice ',
            '--name' => 'Alice Liddell',
            '--given-name' => 'Alice',
            '--family-name' => 'Liddell',
            '--nickname' => 'Ali',
            '--preferred-username' => 'alice',
            '--profile-url' => 'https://alice.example/about',
            '--picture' => 'https://alice.example/alice.png',
            '--website' => 'https://alice.example',
            '--gender' => 'female',
            '--birthdate' => '1990-05-04',
            '--zoneinfo' => 'Europe/London',
            '--locale' => 'en-GB',
            '--phone-number' => '+44 1865 000000',
            '--phone-number-verified' => true,
            '--address' => "1 Wonderland Road\nOxford OX1 1AA\nUnited Kingdom",
            '--street-address' => '1 Wonderland Road',
            '--locality' => 'Oxford',
            '--region' => 'Oxfordshire',
            '--postal-code' => 'OX1 1AA',
            '--country' => 'United Kingdom',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('Alice Liddell', self::displayed($tester, 'Name'));
        static::assertSame('+44 1865 000000 (verified)', self::displayed($tester, 'Phone number'));
        static::assertSame('1 Wonderland Road, OX1 1AA, Oxford, Oxfordshire, United Kingdom', self::displayed($tester, 'Address'));
        $described = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        static::assertSame('Alice Liddell', $described->profile->name);
        static::assertSame('Alice', $described->profile->givenName);
        static::assertSame('Liddell', $described->profile->familyName);
        static::assertNull($described->profile->middleName);
        static::assertSame('Ali', $described->profile->nickname);
        static::assertSame('alice', $described->profile->preferredUsername);
        static::assertSame('https://alice.example/about', $described->profile->profileUrl);
        static::assertSame('https://alice.example/alice.png', $described->profile->pictureUrl);
        static::assertSame('https://alice.example', $described->profile->websiteUrl);
        static::assertSame('female', $described->profile->gender);
        static::assertSame('1990-05-04', $described->profile->birthdate);
        static::assertSame('Europe/London', $described->profile->zoneinfo);
        static::assertSame('en-GB', $described->profile->locale);
        static::assertSame('+44 1865 000000', $described->phoneNumber);
        static::assertTrue($described->phoneNumberVerified);
        $address = $described->address ?? static::fail('The address is not stored.');
        static::assertSame("1 Wonderland Road\nOxford OX1 1AA\nUnited Kingdom", $address->formatted);
        static::assertSame('1 Wonderland Road', $address->streetAddress);
        static::assertSame('Oxford', $address->locality);
        static::assertSame('Oxfordshire', $address->region);
        static::assertSame('OX1 1AA', $address->postalCode);
        static::assertSame('United Kingdom', $address->country);
    }

    /**
     * A run that says nothing is the read the command is not: it writes nothing rather than clearing everything.
     */
    #[Test]
    public function aDescriptionThatSaysNothingWritesNothing(): void
    {
        // Given
        $user = self::user('alice');
        self::console('beffroi:user:profile', [
            'username' => 'alice',
            '--name' => 'Alice Liddell',
        ]);

        // When
        $tester = self::console('beffroi:user:profile', [
            'username' => 'alice',
            '--nickname' => '  ',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('Nothing was said', $tester->getDisplay(true));
        static::assertStringContainsString('beffroi:user:show', $tester->getDisplay(true));
        $described = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        static::assertSame('Alice Liddell', $described->profile->name);
    }

    /**
     * Architecture §5.5: the read, the identity and the claims that are set, nothing written.
     */
    #[Test]
    public function aUserIsShownWithTheirIdentityAndTheClaimsThatAreSet(): void
    {
        // Given
        $user = self::user('alice');
        self::console('beffroi:user:profile', [
            'username' => 'alice',
            '--name' => 'Alice Liddell',
            '--phone-number' => '+44 1865 000000',
        ]);

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => ' alice ',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('alice', self::displayed($tester, 'Username'));
        static::assertSame($user->subject->value, self::displayed($tester, 'Subject'));
        static::assertSame('enabled', self::displayed($tester, 'Status'));
        static::assertSame('Alice Liddell', self::displayed($tester, 'Name'));
        static::assertSame('+44 1865 000000 (unverified)', self::displayed($tester, 'Phone number'));
        static::assertStringNotContainsString('is described', $tester->getDisplay(true));
    }

    #[Test]
    public function anUnknownUserIsNotShown(): void
    {
        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'nobody',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('There is no user named "nobody"', $tester->getDisplay(true));
    }

    /**
     * The whole description every time: what the second run does not say is cleared.
     */
    #[Test]
    public function aSecondDescriptionClearsWhatItDoesNotSay(): void
    {
        // Given
        $user = self::user('alice');
        self::console('beffroi:user:profile', [
            'username' => 'alice',
            '--name' => 'Alice Liddell',
            '--phone-number' => '+44 1865 000000',
            '--phone-number-verified' => true,
            '--locality' => 'Oxford',
        ]);

        // When
        $tester = self::console('beffroi:user:profile', [
            'username' => 'alice',
            '--given-name' => 'Alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $described = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        static::assertNull($described->profile->name);
        static::assertSame('Alice', $described->profile->givenName);
        static::assertNull($described->phoneNumber);
        static::assertFalse($described->phoneNumberVerified);
        static::assertNull($described->address);
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideDescriptionsRefused')]
    public function aDescriptionThatCannotBeTakenIsRefusedWithoutWriting(array $input, int $status, string $message): void
    {
        // Given
        $user = self::user('alice');

        // When
        $tester = self::console('beffroi:user:profile', $input);

        // Then
        static::assertSame($status, $tester->getStatusCode());
        static::assertStringContainsString($message, $tester->getDisplay());
        $described = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        static::assertNull($described->profile->name);
        static::assertNull($described->phoneNumber);
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, int, string}>
     */
    public static function provideDescriptionsRefused(): iterable
    {
        yield 'not a birthdate' => [
            [
                'username' => 'alice',
                '--name' => 'Alice Liddell',
                '--birthdate' => '4 May 1990',
            ],
            Command::INVALID,
            'must be "YYYY-MM-DD" or "YYYY"',
        ];
        yield 'a verified phone number without a number' => [
            [
                'username' => 'alice',
                '--name' => 'Alice Liddell',
                '--phone-number-verified' => true,
            ],
            Command::INVALID,
            'An absent phone number cannot be verified.',
        ];
        yield 'unknown user' => [
            [
                'username' => 'nobody',
                '--name' => 'Nobody',
            ],
            Command::FAILURE,
            'There is no user named "nobody"',
        ];
    }

    /**
     * What a script does: the password on the standard input, its line ending dropped, nothing on the
     * command line.
     */
    #[Test]
    public function thePasswordIsReadFromTheStandardInputForScripts(): void
    {
        // Given
        $user = self::user('alice');

        // When
        $tester = self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
            [self::PASSWORD],
        );

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $credential = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($user, PasswordCredential::class)[0] ?? static::fail('No credential was created.');
        static::assertSame(Argon2id::NAME, $credential->hash->algorithm->name());
        static::assertTrue(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, self::PASSWORD));
        static::assertFalse(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, self::PASSWORD . "\n"));
    }

    #[Test]
    public function aSecondPasswordReplacesTheFirstOnTheSameCredential(): void
    {
        // Given
        $user = self::user('alice');
        self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
            ['the first password posed'],
        );
        $first = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($user, PasswordCredential::class)[0]->id ?? static::fail('No credential was created.');
        self::reload();

        // When
        $tester = self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
            ],
            ['the second password posed', 'the second password posed'],
        );

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $credential = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($user, PasswordCredential::class)[0] ?? static::fail('The credential is gone.');
        static::assertTrue($first->equals($credential->id));
        static::assertTrue(
            self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'the second password posed'),
        );
        static::assertFalse(
            self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'the first password posed'),
        );
    }

    /**
     * The rule NIST SP 800-63B §3.1.1.2 puts first, on the path an operator writes a password for
     * somebody: the console gets it by construction and prints it in one flat line.
     */
    #[Test]
    public function aPasswordAListOfCompromisedPasswordsCountsIsRefused(): void
    {
        // Given
        $user = self::user('alice');
        self::breaches()->names([self::PASSWORD]);

        // When
        $tester = self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
            [self::PASSWORD],
        );

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('list of compromised passwords', $tester->getDisplay());
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($user, PasswordCredential::class));
    }

    /**
     * Decision 0006: an unknown is not a clean answer. Nothing is written, and the operator is told to
     * pose the password again rather than handed one nobody checked.
     */
    #[Test]
    public function aPasswordNoListCouldBeAskedAboutIsRefused(): void
    {
        // Given
        $user = self::user('alice');
        self::breaches()->cannotBeReached();

        // When
        $tester = self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
            [self::PASSWORD],
        );

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('could not be asked', $tester->getDisplay());
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($user, PasswordCredential::class));
    }

    /**
     * What the console asked is written on the credential, so that the first login does not ask again
     * what was just asked.
     */
    #[Test]
    public function thePasswordTheConsoleWroteIsMarkedAsLookedUp(): void
    {
        // Given
        $user = self::user('alice');
        self::breaches()->names(['a password of somebody else']);

        // When
        self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
                '--password-stdin' => true,
            ],
            [self::PASSWORD],
        );

        // Then
        self::reload();
        $credential = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByUser($user, PasswordCredential::class)[0] ?? static::fail('No credential was created.');
        static::assertNotNull($credential->breachCheckedAt);
        static::assertFalse($credential->isBreached());
    }

    /**
     * The list of this kernel, armed by the test that wants the rule; it names nothing otherwise.
     */
    private static function breaches(): BreachedPasswordsOfARecord
    {
        return self::service('test.beffroi.breached_passwords', BreachedPasswordsOfARecord::class);
    }

    /**
     * @param array<string, string|bool> $input
     * @param list<string> $inputs
     */
    #[Test]
    #[DataProvider('providePasswordsRefused')]
    public function aPasswordThatIsNotConfirmedTooShortEmptyOrUnaskableIsRefused(
        array $input,
        array $inputs,
        bool $interactive,
        int $status,
        string $message,
    ): void {
        // Given
        $user = self::user('alice');

        // When
        $tester = self::console('beffroi:user:set-password', $input, $inputs, $interactive);

        // Then
        static::assertSame($status, $tester->getStatusCode());
        static::assertStringContainsString($message, $tester->getDisplay());
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($user, PasswordCredential::class));
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, list<string>, bool, int, string}>
     */
    public static function providePasswordsRefused(): iterable
    {
        $alice = [
            'username' => 'alice',
        ];
        $stdin = $alice
        + [
            '--password-stdin' => true,
        ];
        yield 'not confirmed' => [$alice, [self::PASSWORD, self::PASSWORD . 'r'], true, Command::INVALID, 'The two passwords differ.'];
        yield 'too short' => [$alice, ['short', 'short'], true, Command::INVALID, 'at least 15 characters'];
        yield 'too weak' => [$alice, ['passwordpassword', 'passwordpassword'], true, Command::INVALID, 'short of length and of alphabet'];
        yield 'empty on the terminal' => [$alice, ['', ''], true, Command::INVALID, 'The password is empty.'];
        yield 'empty on the standard input' => [$stdin, [''], true, Command::INVALID, 'The password is empty.'];
        yield 'too long' => [$stdin, [str_repeat('a', 4097)], true, Command::INVALID, 'at most 4096 bytes'];
        yield 'not askable' => [$alice, [], false, Command::INVALID, '--password-stdin'];
        yield 'unknown user' => [
            [
                'username' => 'nobody',
                '--password-stdin' => true,
            ],
            [self::PASSWORD],
            true,
            Command::FAILURE,
            'There is no user named "nobody"',
        ];
    }

    /**
     * Steps 1 to 3 of the acceptance criterion: the tenant, a key, alice with a password, from the console.
     *
     * @return array{kid: string, subject: string}
     */
    private static function provisionAliceFromTheConsole(): array
    {
        self::dropTenant();
        self::console('beffroi:tenant:synchronize');
        $kid = self::displayed(self::console('beffroi:keys:generate'), 'Key identifier');
        $subject = self::displayed(self::console('beffroi:user:create', [
            'username' => 'alice',
            '--email' => 'alice@example.com',
            '--email-verified' => true,
        ]), 'Subject');
        self::console(
            'beffroi:user:set-password',
            [
                'username' => 'alice',
            ],
            [self::PASSWORD, self::PASSWORD],
        );

        return [
            'kid' => $kid,
            'subject' => $subject,
        ];
    }

    /**
     * The code the native client gets once alice signed in on the form and allowed.
     */
    private function codeOfAliceSignedInOnTheForm(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $form = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ])->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($crawler->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * Before the first provisioning: the schema, and no tenant row.
     */
    private static function dropTenant(): void
    {
        self::entityManager()->getConnection()->executeStatement('DELETE FROM beffroi_tenant');
        self::reload();
    }

    private static function base64UrlDecode(string $value): string
    {
        return self::string(base64_decode(strtr($value, '-_', '+/'), true));
    }
}
