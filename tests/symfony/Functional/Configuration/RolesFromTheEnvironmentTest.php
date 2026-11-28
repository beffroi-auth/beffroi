<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Configuration;

use App\Ciba\MailApprovalChannel;
use App\Ciba\SmsApprovalChannel;
use App\Configuration\SwitchedServices;
use App\Credential\CredentialChangeChannels;
use App\Credential\MailToTheReplacedAddressChannel;
use App\Credential\SmsToTheReplacedNumberChannel;
use App\Mail\MailSender;
use App\Saml\SamlSigning;
use App\Sms\SmsSender;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Port\ApplicationServerAlgorithmsInterface;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0030, Decision 0048, Decision 0049, spec/saml.md S-40, S-41, architecture §5.6
 */
final class RolesFromTheEnvironmentTest extends ConsoleTestCase
{
    private const string ENVIRONMENT = 'test_environment_roles';

    private const array VARIABLES = [
        'BEFFROI_TEST_SAML_IDENTITY_PROVIDER',
        'BEFFROI_TEST_SAML_SERVICE_PROVIDER',
        'BEFFROI_TEST_SAML_SERVICE_PROVIDER_ENTITY_ID',
        'BEFFROI_TEST_WEB_PUSH_SUBJECT',
        'BEFFROI_TEST_MAIL_DSN',
        'BEFFROI_TEST_SMS_DSN',
    ];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::ENVIRONMENT,
        ];
    }

    /**
     * Spec/saml.md section 6.1
     */
    #[Test]
    public function anIdentityProviderTheEnvironmentLeavesOnServesItsMetadata(): void
    {
        // Given
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/metadata');

        // Then
        static::assertSame('https://op.test/saml/metadata', $this->servedDescriptor()->entityId);
    }

    /**
     * S-41
     */
    #[Test]
    public function anIdentityProviderTheEnvironmentTurnsOffServesNoMetadata(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_IDENTITY_PROVIDER' => 'false',
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER' => 'true',
        ]);
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Spec/saml.md section 6.9
     */
    #[Test]
    public function aServiceProviderTheEnvironmentTurnsOnServesItsMetadata(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER' => 'true',
        ]);
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame('https://op.test/saml/sp/metadata', $this->servedDescriptor()->entityId);
    }

    /**
     * S-38
     */
    #[Test]
    public function aServiceProviderGoesByTheEntityIdTheEnvironmentNames(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER' => 'true',
            'BEFFROI_TEST_SAML_SERVICE_PROVIDER_ENTITY_ID' => 'urn:example:op:service-provider',
        ]);
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame('urn:example:op:service-provider', $this->servedDescriptor()->entityId);
    }

    /**
     * S-41
     */
    #[Test]
    public function aServiceProviderTheEnvironmentLeavesOffServesNoMetadata(): void
    {
        // Given
        self::drawTheSamlKey();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-40
     */
    #[Test]
    public function aTenantWhoseRolesTheEnvironmentTurnsOffDrawsNoSamlKey(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_SAML_IDENTITY_PROVIDER' => 'false',
        ]);

        // When
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('This provider signs no SAML message with a key named "SAML-SIGNING"; it serves no SAML.', self::flattened($tester));
    }

    /**
     * Spec/saml.md section 5.1
     */
    #[Test]
    public function aSamlKeyDrawnBeforeTheEnvironmentTurnedTheRolesOffIsDormant(): void
    {
        // Given
        self::drawTheSamlKey();
        $this->deploy([
            'BEFFROI_TEST_SAML_IDENTITY_PROVIDER' => 'false',
        ]);

        // When
        $inService = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findInService(self::tenant());

        // Then
        static::assertSame([], $inService);
    }

    /**
     * Architecture §5.6, RFC 8292 §2
     */
    #[Test]
    public function webPushIsOnWhileTheEnvironmentNamesASubject(): void
    {
        // When
        $algorithms = self::applicationServerAlgorithms();

        // Then
        static::assertSame(['VAPID'], $algorithms);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function webPushIsOffWhileTheEnvironmentNamesNoSubject(): void
    {
        // Given
        $this->deploy([
            'BEFFROI_TEST_WEB_PUSH_SUBJECT' => '',
        ]);

        // When
        $algorithms = self::applicationServerAlgorithms();

        // Then
        static::assertSame([], $algorithms);
    }

    /**
     * Decision 0048
     *
     * @param class-string $channel
     */
    #[Test]
    #[DataProvider('provideChannelsOfADsnTheEnvironmentNames')]
    public function aChannelTellsOfAPendingApprovalWhileTheEnvironmentNamesItsDsn(string $channel): void
    {
        // When
        $channels = self::pendingApprovalChannels();

        // Then
        static::assertContains($channel, $channels);
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function provideChannelsOfADsnTheEnvironmentNames(): iterable
    {
        yield 'mail' => [MailApprovalChannel::class];
        yield 'SMS' => [SmsApprovalChannel::class];
    }

    /**
     * Decision 0048
     *
     * @param class-string $channel
     */
    #[Test]
    #[DataProvider('provideChannelsOfADsn')]
    public function aChannelIsAbsentWhileTheEnvironmentNamesNoDsn(string $variable, string $channel): void
    {
        // Given
        $this->deploy([
            $variable => '',
        ]);

        // When
        $channels = self::pendingApprovalChannels();

        // Then
        static::assertNotContains($channel, $channels);
    }

    /**
     * @return iterable<string, array{string, class-string}>
     */
    public static function provideChannelsOfADsn(): iterable
    {
        yield 'mail' => ['BEFFROI_TEST_MAIL_DSN', MailApprovalChannel::class];
        yield 'SMS' => ['BEFFROI_TEST_SMS_DSN', SmsApprovalChannel::class];
    }

    /**
     * Decision 0048, Decision 0049
     */
    #[Test]
    #[DataProvider('provideCredentialChangeChannelsOfADsnTheEnvironmentNames')]
    public function aChannelTellsOfACredentialChangeWhileTheEnvironmentNamesItsDsn(string $channel): void
    {
        // When
        $channels = self::credentialChangeChannels();

        // Then
        static::assertContains($channel, $channels);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCredentialChangeChannelsOfADsnTheEnvironmentNames(): iterable
    {
        yield 'mail' => [MailSender::CHANNEL];
        yield 'SMS' => [SmsSender::CHANNEL];
    }

    /**
     * Decision 0048
     */
    #[Test]
    #[DataProvider('provideCredentialChangeChannelsOfADsn')]
    public function aChannelOfACredentialChangeIsAbsentWhileTheEnvironmentNamesNoDsn(string $variable, string $channel): void
    {
        // Given
        $this->deploy([
            $variable => '',
        ]);

        // When
        $channels = self::credentialChangeChannels();

        // Then
        static::assertNotContains($channel, $channels);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCredentialChangeChannelsOfADsn(): iterable
    {
        yield 'mail' => ['BEFFROI_TEST_MAIL_DSN', MailSender::CHANNEL];
        yield 'SMS' => ['BEFFROI_TEST_SMS_DSN', SmsSender::CHANNEL];
    }

    /**
     * Decision 0048, decision 0049
     */
    #[Test]
    #[DataProvider('provideReplacedChannelsOfADsnTheEnvironmentNames')]
    public function aChannelThatReachesAReplacedOneTellsWhileTheEnvironmentNamesItsDsn(string $claim, string $channel): void
    {
        // When
        $channels = self::service('test.beffroi.environment_roles.credential_change_channels', CredentialChangeChannels::class)->reaching($claim);

        // Then
        static::assertSame([$channel], $channels);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideReplacedChannelsOfADsnTheEnvironmentNames(): iterable
    {
        yield 'mail' => ['email', MailToTheReplacedAddressChannel::NAME];
        yield 'SMS' => ['phone_number', SmsToTheReplacedNumberChannel::NAME];
    }

    /**
     * Decision 0048, decision 0049
     */
    #[Test]
    #[DataProvider('provideReplacedChannelsOfADsn')]
    public function aChannelThatReachesAReplacedOneIsAbsentWhileTheEnvironmentNamesNoDsn(string $variable, string $claim, string $channel): void
    {
        // Given
        $this->deploy([
            $variable => '',
        ]);

        // When
        $channels = self::service('test.beffroi.environment_roles.credential_change_channels', CredentialChangeChannels::class)->reaching($claim);

        // Then
        static::assertNotContains($channel, $channels);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideReplacedChannelsOfADsn(): iterable
    {
        yield 'mail' => ['BEFFROI_TEST_MAIL_DSN', 'email', MailToTheReplacedAddressChannel::NAME];
        yield 'SMS' => ['BEFFROI_TEST_SMS_DSN', 'phone_number', SmsToTheReplacedNumberChannel::NAME];
    }

    /**
     * @param array<string, string> $variables
     */
    private function deploy(array $variables): void
    {
        foreach ($variables as $name => $value) {
            $_SERVER[$name] = $value;
        }
        $this->browser = self::browser(null, self::kernelOptions());
        $this->browser->disableReboot();
    }

    private static function drawTheSamlKey(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * @return list<string>
     */
    private static function applicationServerAlgorithms(): array
    {
        return array_map(
            static fn (KeyAlgorithmInterface $algorithm): string => $algorithm->name(),
            self::service('test.beffroi.environment_roles.application_server_algorithms', ApplicationServerAlgorithmsInterface::class)->all(),
        );
    }

    /**
     * @return list<class-string>
     */
    private static function pendingApprovalChannels(): array
    {
        $channels = [];
        foreach (self::service('test.beffroi.environment_roles.pending_approval_channels', SwitchedServices::class) as $channel) {
            $channels[] = $channel::class;
        }

        return $channels;
    }

    /**
     * @return list<string>
     */
    private static function credentialChangeChannels(): array
    {
        return self::service('test.beffroi.environment_roles.credential_change_channels', CredentialChangeChannels::class)->names();
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }
}
