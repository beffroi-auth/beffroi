<?php

declare(strict_types=1);

/*
 * The model half of "castor saml-idp" (.castor/lab/saml-idp.php, issue #788): the metadata the SimpleSAMLphp identity
 * provider of the stack served, read back by the package the provider reads the metadata of an upstream identity
 * provider with, not by SimpleSAMLphp and not by xmlsec1. readTrusted(), the reading of metadata whose channel vouches
 * for them, finds an identity provider named by the URL of its metadata, its single sign-on service on HTTP-Redirect and
 * on HTTP-POST at https endpoints, the persistent NameID format, and one signing certificate, the one the walk drew;
 * then readSigned() verifies the signature SimpleSAMLphp put on them under that certificate, pinned, and reads the same
 * descriptor (spec/model.md section 6.5, M-2).
 *
 * It reads a directory the walk wrote and nothing else of it:
 *
 *   captured/idp-metadata.xml   the metadata of the identity provider, as it served them
 *   idp.crt                     the certificate of the identity provider, as the walk drew it
 *
 * One line per verification; the exit status is not 0 when one fails, with the rule the model gives. From the root of
 * the repository, in the phpqa image (the walk runs it):
 *
 *   docker run --rm -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/demo/saml-idp-model.php var/saml-idp
 */

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../vendor/autoload.php';

const SAML_IDP_MODEL_ENTITY_ID = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

const SAML_IDP_MODEL_SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

/**
 * @throws RuntimeException when the file cannot be read
 */
function saml_idp_model_file(string $path): string
{
    $contents = file_get_contents($path);
    if ($contents === false) {
        throw new RuntimeException(sprintf('%s cannot be read.', $path));
    }

    return $contents;
}

/**
 * @throws RuntimeException when the condition does not hold, naming what was not verified
 */
function saml_idp_model_verified(bool $condition, string $what): void
{
    if (! $condition) {
        throw new RuntimeException('Not verified: ' . $what);
    }
    printf("  ✓ %s\n", $what);
}

$directory = $argv[1] ?? null;
if ($directory === null || ! is_dir($directory)) {
    throw new InvalidArgumentException('usage: php tests/demo/saml-idp-model.php <directory of the identity provider, var/saml-idp>');
}

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
};
$loader = SamlLoader::create();
$reader = new MetadataReader($loader, $clock);
$document = saml_idp_model_file($directory . '/captured/idp-metadata.xml');
$certificate = saml_idp_model_file($directory . '/idp.crt');
$der = base64_decode((string) preg_replace('~-----[^-]+-----|\s+~', '', $certificate), true);

$descriptor = $reader->readTrusted($loader->load($document));
$idp = $descriptor->identityProvider ?? throw new RuntimeException('Not verified: the metadata hold no identity provider');
saml_idp_model_verified($descriptor->serviceProvider === null, 'readTrusted() reads one identity provider and no service provider');
saml_idp_model_verified($descriptor->entityId === SAML_IDP_MODEL_ENTITY_ID, sprintf('named by the URL of its metadata, %s', SAML_IDP_MODEL_ENTITY_ID));
saml_idp_model_verified(
    array_map(
        static fn (Endpoint $endpoint): array => [$endpoint->binding, $endpoint->location, $endpoint->responseLocation],
        $idp->singleSignOnServices,
    ) === [
        [Binding::HttpRedirect, SAML_IDP_MODEL_SINGLE_SIGN_ON, null],
        [Binding::HttpPost,     SAML_IDP_MODEL_SINGLE_SIGN_ON, null],
    ],
    sprintf('its single sign-on service on HTTP-Redirect and on HTTP-POST, %s', SAML_IDP_MODEL_SINGLE_SIGN_ON),
);
saml_idp_model_verified($idp->nameIdFormats === [NameIdFormat::Persistent], 'the persistent NameID format, and no other');
saml_idp_model_verified(
    is_string($der) && array_map(static fn (string $base64): string|false => base64_decode($base64, true), $idp->signingCertificates) === [$der],
    'one signing certificate, the one drawn for it',
);

$signed = $reader->readSigned($loader->load($document), new VerificationKeys([VerificationKey::fromCertificatePem($certificate)]));
saml_idp_model_verified(
    serialize($signed) === serialize($descriptor),
    'readSigned() verifies their signature under that certificate, pinned, and reads the same identity provider',
);
