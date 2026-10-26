<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Command\SamlIdentityProviderForgetCommand;
use Beffroi\Bundle\Command\SamlIdentityProviderRefreshCommand;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Message\RefreshTheSamlMetadata;
use Beffroi\Bundle\MessageHandler\RefreshTheSamlMetadataHandler;
use Beffroi\Bundle\Tests\Fixture\RecordedMessages;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use DateTimeImmutable;
use function dirname;
use function file_put_contents;
use function is_dir;
use function mkdir;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LogLevel;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * beffroi/saml, spec/saml.md S-42, S-6, section 6.10, the acceptance of issue #779: the SimpleSAMLphp identity provider
 * of the judge the configuration of a deployment whose tenant is a service provider declares
 * (tests/symfony/config/config_test_service_provider.yml), registered by "beffroi:saml:identity-provider:refresh" from
 * its metadata, a file of the deployment, at 2026-09-15T10:00:00Z.
 */
final class UpstreamIdentityProvidersTest extends ConsoleTestCase
{
    /**
     * The environment whose configuration enables the service provider and declares the identity provider.
     */
    private const string SERVICE_PROVIDER = 'test_service_provider';

    protected function setUp(): void
    {
        parent::setUp();
        self::mockTime(new DateTimeImmutable('2026-09-15T10:00:00+00:00'));
    }

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * The acceptance of issue #779: the SimpleSAMLphp identity provider of the judge is registered by command from its
     * metadata, the bytes that were read kept in the table of the upstream identity providers (S-8, S-42).
     */
    #[Test]
    public function theIdentityProviderOfTheJudgeIsRegisteredByCommandFromItsMetadata(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhp());

        // When
        $tester = self::console(SamlIdentityProviderRefreshCommand::NAME);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('The identity provider "%s" is registered from its metadata.', IdentityProviderDocuments::SIMPLESAMLPHP),
            self::flattened($tester),
        );
        $accepted = self::accepted();
        static::assertInstanceOf(AcceptedUpstreamMetadata::class, $accepted);
        static::assertSame(IdentityProviderDocuments::simpleSamlPhp(), $accepted->document);
    }

    /**
     * S-42: one identity provider is refreshed by its entity ID.
     */
    #[Test]
    public function oneIdentityProviderIsRefreshedByItsEntityId(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhp());

        // When
        $tester = self::console(SamlIdentityProviderRefreshCommand::NAME, [
            'entity-id' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(IdentityProviderDocuments::simpleSamlPhp(), self::accepted()?->document);
    }

    /**
     * S-42: an entity ID the configuration does not declare is refused as invalid, and nothing is read.
     */
    #[Test]
    public function anIdentityProviderNobodyDeclaredIsRefused(): void
    {
        // When
        $tester = self::console(SamlIdentityProviderRefreshCommand::NAME, [
            'entity-id' => 'https://idp.nobody.example/saml',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The tenant declares no identity provider "https://idp.nobody.example/saml"; declare it under "beffroi.saml.identity_providers" first.',
            self::flattened($tester),
        );
    }

    /**
     * S-42, S-6: an expired document is refused by the command, which fails, and the accepted one kept.
     */
    #[Test]
    public function anExpiredDocumentIsRefusedAndTheAcceptedOneKept(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));
        self::console(SamlIdentityProviderRefreshCommand::NAME);
        self::publish(IdentityProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:00:00Z'));

        // When
        $tester = self::console(SamlIdentityProviderRefreshCommand::NAME);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The metadata is past its validUntil (M-7).', self::flattened($tester));
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), self::accepted()?->validUntil);
    }

    /**
     * S-42, S-6: the forget command removes the accepted document of an identity provider.
     */
    #[Test]
    public function theForgetCommandRemovesTheAcceptedDocument(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhp());
        self::console(SamlIdentityProviderRefreshCommand::NAME);

        // When
        $tester = self::console(SamlIdentityProviderForgetCommand::NAME, [
            'entity-id' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNull(self::accepted());
    }

    /**
     * S-6: an entity ID nothing is accepted for is answered as invalid, and nothing is forgotten.
     */
    #[Test]
    public function anIdentityProviderWithNothingAcceptedIsNotForgotten(): void
    {
        // When
        $tester = self::console(SamlIdentityProviderForgetCommand::NAME, [
            'entity-id' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            sprintf('No metadata are accepted for the identity provider "%s": nothing is forgotten.', IdentityProviderDocuments::SIMPLESAMLPHP),
            self::flattened($tester),
        );
    }

    /**
     * Section 6.10: the hourly step of the schedule refreshes the upstream identity providers with the service
     * providers, by the object the command runs.
     */
    #[Test]
    public function theStepOfTheScheduleRegistersTheIdentityProvider(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhp());

        // When
        self::service('command.bus', MessageBusInterface::class)->dispatch(new RefreshTheSamlMetadata());

        // Then
        static::assertInstanceOf(AcceptedUpstreamMetadata::class, self::accepted());
    }

    /**
     * S-6, section 6.10: a document the step of the schedule refuses is written to the log as an error, the level an
     * operator is alerted on.
     */
    #[Test]
    public function aDocumentTheStepOfTheScheduleRefusesIsLoggedAsAnError(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey());
        $said = new RecordedMessages();
        /** @var ServiceLocator<MetadataRefresh<covariant PeerInterface>> $roles */
        $roles = new ServiceLocator([
            'beffroi.saml.identity_providers.refresh' => static fn (): MetadataRefresh => self::service(
                'beffroi.saml.identity_providers.refresh',
                MetadataRefresh::class,
            ),
        ]);
        $step = new RefreshTheSamlMetadataHandler(self::service(TenantProvider::class, TenantProvider::class), $roles, $said);

        // When
        $step(new RefreshTheSamlMetadata());

        // Then
        static::assertSame(
            [sprintf(
                'The metadata of the identity provider "%s" are refused, the document accepted kept: The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).',
                IdentityProviderDocuments::SIMPLESAMLPHP,
            )],
            $said->at(LogLevel::ERROR),
        );
    }

    /**
     * Section 6.10: a role whose declarations are refused when its refresh is built, at the first use of declarations
     * holding an environment variable, is written to the log as an error, and the next role is read.
     */
    #[Test]
    public function aRoleRefusedAtItsFirstUseIsLoggedAndTheNextRoleRead(): void
    {
        // Given
        self::publish(IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey());
        $said = new RecordedMessages();
        /** @var ServiceLocator<MetadataRefresh<covariant PeerInterface>> $roles */
        $roles = new ServiceLocator([
            'beffroi.saml.service_providers.refresh' =>
                static fn (): MetadataRefresh => throw new InvalidArgumentException('The service provider "https://sp.example.com/saml": The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).'),
            'beffroi.saml.identity_providers.refresh' => static fn (): MetadataRefresh => self::service(
                'beffroi.saml.identity_providers.refresh',
                MetadataRefresh::class,
            ),
        ]);
        $step = new RefreshTheSamlMetadataHandler(self::service(TenantProvider::class, TenantProvider::class), $roles, $said);

        // When
        $step(new RefreshTheSamlMetadata());

        // Then
        static::assertSame(
            [
                'The SAML metadata of the role "beffroi.saml.service_providers.refresh" could not be refreshed, the next role is read: Beffroi\\Core\\Exception\\InvalidArgumentException was thrown: The service provider "https://sp.example.com/saml": The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).',
                sprintf(
                    'The metadata of the identity provider "%s" are refused, the document accepted kept: The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).',
                    IdentityProviderDocuments::SIMPLESAMLPHP,
                ),
            ],
            $said->at(LogLevel::ERROR),
        );
    }

    /**
     * The file the declaration of the test names, in the cache directory of the kernel of this worker.
     */
    private static function publish(string $document): void
    {
        $kernel = self::$kernel ?? static::fail('The kernel is not booted.');
        $path = $kernel->getCacheDir() . '/saml/simplesamlphp-idp-metadata.xml';
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0o777, true);
        }
        file_put_contents($path, $document);
    }

    private static function accepted(): ?AcceptedMetadata
    {
        self::reload();

        return self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->find(
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
            );
    }
}
