<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataWriter;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Tests\Fixture\FixedServiceProviderEndpoints;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use function array_map;
use function file_put_contents;
use function getenv;
use function is_dir;
use function json_encode;
use function mkdir;
use PHPUnit\Framework\Attributes\RequiresEnvironmentVariable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 9, S-39: the metadata of the service provider of a tenant holding an active and a staged SAML
 * key, written into the directory SAML_SP_METADATA_ORACLE names with what a reader must find in them, for SimpleSAMLphp's
 * own parser to read ("castor saml-simplesamlphp-parser", tests/saml/Interop/simplesamlphp/). The files are the input
 * of that judge, not fixtures: the test is skipped when the variable is not set.
 */
#[RequiresEnvironmentVariable('SAML_SP_METADATA_ORACLE')]
final class ServiceProviderMetadataOracleTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    /**
     * S-39, S-40, section 6.9: the document, and its entity ID, its assertion consumer service and the certificates of
     * its two keys, in creation order.
     */
    #[Test]
    public function itWritesTheMetadataForSimpleSamlPhp(): void
    {
        // Given
        $tenant = Fixtures::tenant('acme', self::ISSUER);
        $keys = new InMemoryTenantKeyRepository();
        $active = SamlKeys::activeKey($tenant);
        $staged = SamlKeys::key($tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $keys->save($active);
        $keys->save($staged);
        $handler = new ServiceProviderMetadataHandler(
            new SigningCertificates($keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new EncryptionCertificates($keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new FixedServiceProviderEndpoints(),
            new ModelServiceProviderMetadataWriter(),
        );

        // When
        $metadata = $handler->handle($tenant);

        // Then
        static::assertNotFalse($this->put('sp-metadata.xml', $metadata->document));
        static::assertNotFalse($this->put('expected.json', json_encode(
            [
                'entityId' => self::ISSUER . FixedServiceProviderEndpoints::METADATA,
                'assertionConsumerService' => self::ISSUER . FixedServiceProviderEndpoints::ASSERTION_CONSUMER_SERVICE,
                'certificates' => array_map(
                    static fn (TenantKey $key): string => new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($key))->base64,
                    [$active, $staged],
                ),
            ],
            \JSON_THROW_ON_ERROR | \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES,
        )));
    }

    private function put(string $name, string $contents): int|false
    {
        $directory = (string) getenv('SAML_SP_METADATA_ORACLE');
        if (! is_dir($directory)) {
            mkdir($directory, 0o755, true);
        }

        return file_put_contents($directory . '/' . $name, $contents);
    }
}
