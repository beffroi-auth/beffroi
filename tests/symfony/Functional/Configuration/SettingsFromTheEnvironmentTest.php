<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Configuration;

use Beffroi\Bundle\Configuration\TokensSection;
use Beffroi\Bundle\Dpop\CachedDpopNonce;
use Beffroi\Bundle\Http\LogoutTokenSender;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Oidc\Bridge\Null\NoDpopNonce;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Throwable;

/**
 * Issue #911: what a deployment chooses is an environment variable, and a variable is a value only once the
 * container runs. The kernel of these tests reads its settings the way the application does
 * (config_test.yml), so each test names its value before it boots one, as a deployment names it before it
 * starts: the bounds and the rules of the tree hold it all the same, and a requirement it switches on is
 * the class the provider is wired with.
 */
final class SettingsFromTheEnvironmentTest extends KernelTestCase
{
    private const array VARIABLES = [
        'BEFFROI_TEST_AUTHORIZATION_CODE_TTL',
        'BEFFROI_TEST_ACCESS_TOKEN_TTL',
        'BEFFROI_TEST_ID_TOKEN_TTL',
        'BEFFROI_TEST_REFRESH_TOKEN_TTL',
        'BEFFROI_TEST_REFRESH_TOKEN_ABSOLUTE_TTL',
        'BEFFROI_TEST_STAGING_DELAY',
        'BEFFROI_TEST_DPOP_NONCE_REQUIRED',
        'BEFFROI_TEST_DEVICE_CODE_INTERVAL',
        'BEFFROI_TEST_BACKCHANNEL_AUTHENTICATION_INTERVAL',
        'BEFFROI_TEST_ORIGIN_BUDGET',
        'BEFFROI_TEST_ORIGIN_INTERVAL',
        'BEFFROI_TEST_CLIENT_BUDGET',
        'BEFFROI_TEST_CLIENT_INTERVAL',
        'BEFFROI_TEST_WEB_PUSH_SUBJECT',
        'BEFFROI_TEST_TENANT_SLUG',
        'BEFFROI_TEST_SAML_STAGING_DELAY',
        'BEFFROI_TEST_SAML_KEY_AGE',
        'BEFFROI_TEST_SAML_CACHE_DURATION',
        'BEFFROI_TEST_DPOP_PROOF_MAX_AGE',
        'BEFFROI_TEST_DPOP_LEEWAY',
        'BEFFROI_TEST_DPOP_NONCE_TTL',
        'BEFFROI_TEST_BACKCHANNEL_AUTHENTICATION_MAX_REQUESTED_EXPIRY',
        'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_TIMEOUT',
        'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRIES',
        'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRY_DELAY',
        'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRY_MULTIPLIER',
        'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRY_MAX_DELAY',
        'BEFFROI_TEST_CLIENT_NOTIFICATION_TIMEOUT',
        'BEFFROI_TEST_WEB_PUSH_TIMEOUT',
        'BEFFROI_TEST_BREACHED_PASSWORDS_TIMEOUT',
        'BEFFROI_TEST_CLIENT_ASSERTION_MAX_LIFETIME',
        'BEFFROI_TEST_CLIENT_ASSERTION_LEEWAY',
        'BEFFROI_TEST_JWKS_TIMEOUT',
        'BEFFROI_TEST_JWKS_MAX_SIZE',
        'BEFFROI_TEST_JWKS_TTL',
        'BEFFROI_TEST_JWKS_REFETCH_COOLDOWN',
        'BEFFROI_TEST_REQUEST_OBJECT_MAX_LIFETIME',
        'BEFFROI_TEST_REQUEST_OBJECT_LEEWAY',
        'BEFFROI_TEST_REQUEST_OBJECT_TIMEOUT',
        'BEFFROI_TEST_REQUEST_OBJECT_MAX_SIZE',
        'BEFFROI_TEST_KEEP_A_CLIENT_UNUSED_FOR',
        'BEFFROI_TEST_KEEP_A_CLIENT_NEVER_USED_FOR',
        'BEFFROI_TEST_SECTOR_IDENTIFIER_TIMEOUT',
        'BEFFROI_TEST_SECTOR_IDENTIFIER_MAX_SIZE',
        'BEFFROI_TEST_STATEMENT_MAX_LIFETIME',
        'BEFFROI_TEST_STATEMENT_LEEWAY',
        'BEFFROI_TEST_LOGIN_HINT',
        'BEFFROI_TEST_CIBA_LOGIN_HINT',
    ];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    /**
     * RFC 6749 §4.1.2, the recommendation the tree makes a bound: a number the environment carries past it
     * stops the issuer of the codes from being built, as the same number written in the file stops the build
     * of the container.
     */
    #[Test]
    public function aLifetimeTheEnvironmentCarriesPastItsBoundIsRefused(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_AUTHORIZATION_CODE_TTL'] = (string) (TokensSection::MAX_AUTHORIZATION_CODE_TTL + 1);
        self::bootKernel();

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "authorization_code_ttl" is a number of seconds from 1 to 600, 601 given.');

        // When
        static::getContainer()->get('test.beffroi.authorization_code_issuer');
    }

    /**
     * Architecture §4.6: no rotation carries a refresh token past the absolute lifetime of its family, ninety
     * days by default.
     */
    #[Test]
    public function aSlidingRefreshLifetimeTheEnvironmentCarriesBeyondTheAbsoluteOneIsRefused(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_REFRESH_TOKEN_TTL'] = '7776001';
        self::bootKernel();

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).');

        // When
        static::getContainer()->get('test.beffroi.token_issuer');
    }

    /**
     * Issues #913 and #915: a value the tree refuses written, carried by the environment, refuses the build of
     * the service it reaches, whichever object holds the rule: the number (BoundedNumber), the record of a flow
     * that polls, the budget, the retry policy, the factory of the tenant, the handler of the SAML metadata, the
     * readings of a hint, the sender.
     *
     * @param class-string<Throwable> $refusal
     */
    #[Test]
    #[DataProvider('provideValuesOutOfARuleOfTheTree')]
    public function aValueOutOfARuleOfTheTreeRefusesTheServiceItReaches(
        string $variable,
        string $value,
        string $service,
        string $refusal,
        string $message,
    ): void {
        // Given
        $_SERVER[$variable] = $value;
        self::bootKernel();

        // Then
        $this->expectException($refusal);
        $this->expectExceptionMessageIs($message);

        // When
        static::getContainer()->get($service);
    }

    /**
     * @return iterable<string, array{string, string, string, class-string<Throwable>, string}>
     */
    public static function provideValuesOutOfARuleOfTheTree(): iterable
    {
        yield 'an access token that lasts no time' => [
            'BEFFROI_TEST_ACCESS_TOKEN_TTL',
            '0',
            'test.beffroi.jwt_access_token_issuer',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "access_token_ttl" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'an ID token that lasts no time' => [
            'BEFFROI_TEST_ID_TOKEN_TTL',
            '0',
            'test.beffroi.jwt_id_token_issuer',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "id_token_ttl" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a refresh token renewed for no time' => [
            'BEFFROI_TEST_REFRESH_TOKEN_TTL',
            '0',
            'test.beffroi.token_issuer',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "refresh_token_ttl" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a family of refresh tokens that lasts no time' => [
            'BEFFROI_TEST_REFRESH_TOKEN_ABSOLUTE_TTL',
            '0',
            'test.beffroi.what_a_token_still_needs',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "refresh_token_absolute_ttl" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a device code polled past what a client can respect' => [
            'BEFFROI_TEST_DEVICE_CODE_INTERVAL',
            '31',
            'test.beffroi.device_authorization_handler',
            InvalidArgumentException::class,
            'A device authorization request announces a polling interval of at most 30 seconds, a client respecting it (RFC 8628 section 3.5); 31 given.',
        ];
        yield 'a backchannel request polled past what a client can respect' => [
            'BEFFROI_TEST_BACKCHANNEL_AUTHENTICATION_INTERVAL',
            '31',
            'test.beffroi.backchannel_authentication_handler',
            InvalidArgumentException::class,
            'A backchannel authentication request announces a polling interval of at most 30 seconds, a client respecting it (CIBA Core section 11); 31 given.',
        ];
        yield 'a budget of origin for no request' => [
            'BEFFROI_TEST_ORIGIN_BUDGET',
            '0',
            'test.beffroi.origin_load',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "load.origin.limit" is a number of requests of at least 1, 0 given.',
        ];
        yield 'a window of the budget of origin that lasts no time' => [
            'BEFFROI_TEST_ORIGIN_INTERVAL',
            '0',
            'test.beffroi.origin_load',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "load.origin.interval" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a budget of client for no request' => [
            'BEFFROI_TEST_CLIENT_BUDGET',
            '0',
            'test.beffroi.client_load',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "load.client.limit" is a number of requests of at least 1, 0 given.',
        ];
        yield 'a window of the budget of client that lasts no time' => [
            'BEFFROI_TEST_CLIENT_INTERVAL',
            '0',
            'test.beffroi.client_load',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "load.client.interval" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'an empty subject of web push' => [
            'BEFFROI_TEST_WEB_PUSH_SUBJECT',
            '',
            'test.beffroi.web_push_sender',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "web_push.subject" names the "mailto:" or "https:" URI a push service can reach the operator at (RFC 8292 section 2.1), and it is empty.',
        ];
        yield 'an empty slug of the tenant' => [
            'BEFFROI_TEST_TENANT_SLUG',
            '',
            'test.beffroi.tenant_factory',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "tenant.slug" is the stable name of the tenant, and it is empty.',
        ];
        yield 'a SAML key staged for less than no time' => [
            'BEFFROI_TEST_SAML_STAGING_DELAY',
            '-1',
            'test.beffroi.saml_rotation_schedule',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "saml.keys.staging_delay" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a SAML key that works no time' => [
            'BEFFROI_TEST_SAML_KEY_AGE',
            '0',
            'test.beffroi.saml_rotation_schedule',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "saml.keys.age" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'SAML metadata kept for no time' => [
            'BEFFROI_TEST_SAML_CACHE_DURATION',
            '0',
            'test.beffroi.saml_identity_provider_metadata',
            CoreInvalidArgumentException::class,
            'The cacheDuration of the metadata is a number of seconds, one at least (spec/saml.md S-12).',
        ];
        yield 'SAML metadata kept until the next key signs' => [
            'BEFFROI_TEST_SAML_CACHE_DURATION',
            '604800',
            'test.beffroi.saml_identity_provider_metadata',
            CoreInvalidArgumentException::class,
            'The cacheDuration of the metadata, 604800 s, is shorter than the staging delay of a SAML key, 604800 s, or a service provider that honours it meets the next key before its certificate (spec/saml.md S-12).',
        ];
        yield 'a DPoP proof that stands no time' => [
            'BEFFROI_TEST_DPOP_PROOF_MAX_AGE',
            '0',
            'test.beffroi.dpop_proof_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "dpop.proof_max_age" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a leeway of the clock of a DPoP client below none' => [
            'BEFFROI_TEST_DPOP_LEEWAY',
            '-1',
            'test.beffroi.dpop_proof_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "dpop.leeway" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a DPoP nonce accepted for no time' => [
            'BEFFROI_TEST_DPOP_NONCE_TTL',
            '0',
            'test.beffroi.cached_dpop_nonce',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "dpop.nonce.ttl" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a backchannel request asked for past an hour' => [
            'BEFFROI_TEST_BACKCHANNEL_AUTHENTICATION_MAX_REQUESTED_EXPIRY',
            '3601',
            'test.beffroi.backchannel_authentication_handler',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "backchannel_authentication_max_requested_expiry" is a number of seconds from 1 to 3600, 3601 given.',
        ];
        yield 'a logout token given no time' => [
            'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_TIMEOUT',
            '0',
            'test.beffroi.logout_token_sender',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "back_channel_logout.timeout" is a number of seconds of at least 0.1, 0 given.',
        ];
        yield 'fewer than no retry of a notification' => [
            'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRIES',
            '-1',
            'test.beffroi.notification_retry_policy',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "back_channel_logout.retries" is a number of retries of at least 0, -1 given.',
        ];
        yield 'a first retry of a notification at once' => [
            'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRY_DELAY',
            '0',
            'test.beffroi.notification_retry_policy',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "back_channel_logout.retry_delay" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'waits of the retries multiplied by nothing' => [
            'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRY_MULTIPLIER',
            '0',
            'test.beffroi.notification_retry_policy',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "back_channel_logout.retry_multiplier" is a number of times of at least 1, 0 given.',
        ];
        yield 'a ceiling of the waits of nothing' => [
            'BEFFROI_TEST_BACK_CHANNEL_LOGOUT_RETRY_MAX_DELAY',
            '0',
            'test.beffroi.notification_retry_policy',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "back_channel_logout.retry_max_delay" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a client notification given no time' => [
            'BEFFROI_TEST_CLIENT_NOTIFICATION_TIMEOUT',
            '0',
            'test.beffroi.client_notification_sender',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "backchannel_authentication.client_notification_timeout" is a number of seconds of at least 0.1, 0 given.',
        ];
        yield 'a push given no time' => [
            'BEFFROI_TEST_WEB_PUSH_TIMEOUT',
            '0',
            'test.beffroi.web_push_sender',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "web_push.timeout" is a number of seconds of at least 0.1, 0 given.',
        ];
        yield 'the list of compromised passwords given no time' => [
            'BEFFROI_TEST_BREACHED_PASSWORDS_TIMEOUT',
            '0.05',
            'test.beffroi.pwned_passwords',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "passwords.breached.timeout" is a number of seconds of at least 0.1, 0.05 given.',
        ];
        yield 'a client assertion that stands no time' => [
            'BEFFROI_TEST_CLIENT_ASSERTION_MAX_LIFETIME',
            '0',
            'test.beffroi.client_assertion_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.assertion_max_lifetime" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a leeway of the clock of a client below none' => [
            'BEFFROI_TEST_CLIENT_ASSERTION_LEEWAY',
            '-1',
            'test.beffroi.client_assertion_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.assertion_leeway" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a leeway of the clock of a trusted issuer below none' => [
            'BEFFROI_TEST_CLIENT_ASSERTION_LEEWAY',
            '-1',
            'test.beffroi.issuer_assertion_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.assertion_leeway" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a read of a published set given no time' => [
            'BEFFROI_TEST_JWKS_TIMEOUT',
            '0',
            'test.beffroi.client_jwks_fetcher',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.jwks_timeout" is a number of seconds of at least 0.1, 0 given.',
        ];
        yield 'a published set of no byte' => [
            'BEFFROI_TEST_JWKS_MAX_SIZE',
            '0',
            'test.beffroi.client_jwks_fetcher',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.jwks_max_size" is a number of bytes of at least 1, 0 given.',
        ];
        yield 'a published set kept for no time' => [
            'BEFFROI_TEST_JWKS_TTL',
            '0',
            'test.beffroi.client_keys_cache',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.jwks_ttl" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a cooldown of the reads of a published set below none' => [
            'BEFFROI_TEST_JWKS_REFETCH_COOLDOWN',
            '-1',
            'test.beffroi.client_keys_provider',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_authentication.jwks_refetch_cooldown" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a request object that stands no time' => [
            'BEFFROI_TEST_REQUEST_OBJECT_MAX_LIFETIME',
            '0',
            'test.beffroi.request_object_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "request_objects.max_lifetime" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a leeway of the clock of a request object below none' => [
            'BEFFROI_TEST_REQUEST_OBJECT_LEEWAY',
            '-1',
            'test.beffroi.request_object_validator',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "request_objects.leeway" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a read of a request_uri given no time' => [
            'BEFFROI_TEST_REQUEST_OBJECT_TIMEOUT',
            '0',
            'test.beffroi.request_object_fetcher',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "request_objects.timeout" is a number of seconds of at least 0.1, 0 given.',
        ];
        yield 'a request object of no byte' => [
            'BEFFROI_TEST_REQUEST_OBJECT_MAX_SIZE',
            '0',
            'test.beffroi.request_object_fetcher',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "request_objects.max_size" is a number of bytes of at least 1, 0 given.',
        ];
        yield 'a used client kept for no time' => [
            'BEFFROI_TEST_KEEP_A_CLIENT_UNUSED_FOR',
            '0',
            'test.beffroi.registration_policy',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_registration.keep_a_client_unused_for" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a client never used kept for no time' => [
            'BEFFROI_TEST_KEEP_A_CLIENT_NEVER_USED_FOR',
            '0',
            'test.beffroi.registration_policy',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_registration.keep_a_client_never_used_for" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a read of a sector identifier given no time' => [
            'BEFFROI_TEST_SECTOR_IDENTIFIER_TIMEOUT',
            '0',
            'test.beffroi.sector_identifier_fetcher',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_registration.sector_identifier_timeout" is a number of seconds of at least 0.1, 0 given.',
        ];
        yield 'a sector identifier document of no byte' => [
            'BEFFROI_TEST_SECTOR_IDENTIFIER_MAX_SIZE',
            '0',
            'test.beffroi.sector_identifier_fetcher',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_registration.sector_identifier_max_size" is a number of bytes of at least 1, 0 given.',
        ];
        yield 'a software statement that stands no time' => [
            'BEFFROI_TEST_STATEMENT_MAX_LIFETIME',
            '0',
            'test.beffroi.software_statement_verifier',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_registration.statement_max_lifetime" is a number of seconds of at least 1, 0 given.',
        ];
        yield 'a leeway of the clock of an authority below none' => [
            'BEFFROI_TEST_STATEMENT_LEEWAY',
            '-1',
            'test.beffroi.software_statement_verifier',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "client_registration.statement_leeway" is a number of seconds of at least 0, -1 given.',
        ];
        yield 'a login hint read by no reading of the login page' => [
            'BEFFROI_TEST_LOGIN_HINT',
            'email',
            'test.beffroi.login_hints',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "interaction.login_hint" names one of "sub", "username", "none", "email" given.',
        ];
        yield 'a login hint read by no reading of a backchannel request' => [
            'BEFFROI_TEST_CIBA_LOGIN_HINT',
            'email',
            'test.beffroi.user_hints',
            InvalidConfigurationException::class,
            'The "beffroi" configuration key "backchannel_authentication.login_hint" names one of "sub", "username", "none", "email" given.',
        ];
    }

    /**
     * Architecture §3.3: a variable left empty is no delay configured, so the delay follows the max-age of the
     * JWK Set, 120 s in this kernel, plus the refetch cooldown of oidc_login.
     */
    #[Test]
    #[DataProvider('provideStagingDelays')]
    public function theStagingDelayOfTheJoseKeysIsTheOneTheEnvironmentNames(string $variable, int $seconds): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_STAGING_DELAY'] = $variable;
        self::bootKernel();

        // When
        $schedule = static::getContainer()->get('test.beffroi.rotation_schedule');

        // Then
        static::assertInstanceOf(RotationSchedule::class, $schedule);
        static::assertSame($seconds, $schedule->stagingDelay->s);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideStagingDelays(): iterable
    {
        yield 'nothing' => ['', 180];
        yield 'a week' => ['604800', 604800];
    }

    /**
     * Spec/saml.md S-12, issue #915: the family of the SAML keys rotates by the figures the environment names, a key
     * published the moment it is staged among them, which the tree lets a deployment write.
     */
    #[Test]
    public function theScheduleOfTheSamlKeysIsTheOneTheEnvironmentNames(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SAML_STAGING_DELAY'] = '0';
        $_SERVER['BEFFROI_TEST_SAML_KEY_AGE'] = '86400';
        self::bootKernel();

        // When
        $schedule = static::getContainer()->get('test.beffroi.saml_rotation_schedule');

        // Then
        static::assertInstanceOf(RotationSchedule::class, $schedule);
        static::assertSame([0, 86_400], [$schedule->stagingDelay->s, $schedule->age->s]);
    }

    /**
     * Back-Channel Logout 1.0 §2.5, issue #915: one attempt at delivering a logout token is given the time the
     * environment names, a fraction of a second included.
     */
    #[Test]
    public function aLogoutTokenIsGivenTheTimeTheEnvironmentNames(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_BACK_CHANNEL_LOGOUT_TIMEOUT'] = '1.5';
        self::bootKernel();

        // When
        $sender = static::getContainer()->get('test.beffroi.logout_token_sender');

        // Then
        static::assertInstanceOf(LogoutTokenSender::class, $sender);
        static::assertSame(1.5, $sender->timeout->seconds);
    }

    /**
     * RFC 9449 §8: the requirement is read once, when the port is built, and is the class it is built as.
     *
     * @param class-string $wired
     */
    #[Test]
    #[DataProvider('provideNonceRequirements')]
    public function theNonceADpopProofIsAskedForIsTheOneTheEnvironmentRequires(string $variable, string $wired): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_DPOP_NONCE_REQUIRED'] = $variable;
        self::bootKernel();

        // When
        $nonce = static::getContainer()->get('test.beffroi.dpop_nonce');

        // Then
        static::assertInstanceOf($wired, $nonce);
    }

    /**
     * @return iterable<string, array{string, class-string}>
     */
    public static function provideNonceRequirements(): iterable
    {
        yield 'required' => ['true', CachedDpopNonce::class];
        yield 'not required' => ['false', NoDpopNonce::class];
    }
}
