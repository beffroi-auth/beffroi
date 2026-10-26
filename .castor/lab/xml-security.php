<?php

declare(strict_types=1);

/*
 * beffroi/xml-security against xmlsec1, the implementation that is not this one (spec/dsig.md and spec/enc.md,
 * section 9.3): a file verified or decrypted by hand, and the oracle the CI runs, every scheme of the build signed
 * and encrypted in the phpqa image, then verified and decrypted by xmlsec1 in Alpine.
 */

use Castor\Attribute\AsArgument;
use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\io;
use function Castor\run;

/**
 * Where the oracle writes what it signed and encrypted, under the ignored var/.
 */
const XML_SECURITY_ORACLE = 'var/oracle/xml-security';

#[AsTask(
    description: 'Verify a signed XML file with xmlsec1 (spec/dsig.md section 9.1), in an Alpine container: castor xml-security-xmlsec tests/xml-security/Dsig/Fixture/vectors/response-assertion-rsa-sha256.xml',
)]
function xml_security_xmlsec(
    #[AsArgument(description: 'The signed file, relative to the working directory')]
    string $file,
    #[AsOption(description: 'The certificate whose key verifies, relative to the working directory')]
    string $certificate = 'tests/xml-security/Dsig/Fixture/keys/test-signing-certificate.pem',
    #[AsOption(description: 'The Id of the ds:Signature to verify when the file holds several')]
    string $node = '',
    #[AsOption(description: 'An XPath naming the ds:Signature to verify, for one that carries no Id')]
    string $xpath = '',
): void {
    in_alpine(
        'apk add -q xmlsec >/dev/null 2>&1 && xmlsec1 --verify --lax-key-search --pubkey-cert-pem '
            . escapeshellarg($certificate)
            . ' --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion'
            . ' --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response'
            . ' --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor'
            . ' --id-attr:Id http://www.w3.org/2000/09/xmldsig#:Signature'
            . ($node === '' ? '' : ' --node-id ' . escapeshellarg($node))
            . ($xpath === '' ? '' : ' --node-xpath ' . escapeshellarg($xpath))
            . ' '
            . escapeshellarg($file),
        [$certificate, $file],
    );
}

#[AsTask(
    description: 'Decrypt an encrypted XML file with xmlsec1 (spec/enc.md section 9.3), in an Alpine container, and print the plaintext document: castor xml-security-xmlsec-decrypt tests/xml-security/Enc/Fixture/behaviour/encrypted-by-the-encryptor-aes256-gcm.xml',
)]
function xml_security_xmlsec_decrypt(
    #[AsArgument(description: 'The encrypted file, relative to the working directory')]
    string $file,
    #[AsOption(description: 'The private key that unwraps the session key, relative to the working directory')]
    string $key = 'tests/xml-security/Enc/Fixture/keys/test-signing-key.pem',
): void {
    in_alpine(
        'apk add -q xmlsec >/dev/null 2>&1 && xmlsec1 --decrypt --lax-key-search --privkey-pem ' . escapeshellarg($key) . ' ' . escapeshellarg($file),
        [$key, $file],
    );
}

#[AsTask(
    description: 'Sign a response and its assertion with every scheme this build offers and encrypt the assertion under every one, then have xmlsec1 verify and decrypt each (spec/dsig.md and spec/enc.md, section 9.3 row 10), what the job Oracle of the CI runs: PHP_VERSION=8.5 castor xml-security-oracle',
)]
function xml_security_oracle(): void
{
    foreach ([...(glob(XML_SECURITY_ORACLE . '/*.xml') ?: []), ...(glob(XML_SECURITY_ORACLE . '/enc/*') ?: [])] as $file) {
        unlink($file);
    }
    phpqa(
        [
            'composer',
            'exec',
            '--',
            'phpunit',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--no-coverage',
            '--testsuite',
            'xml-security',
            '--filter',
            'SignerOracleTest|EncryptorOracleTest',
        ],
        ['XMLSEC_ORACLE' => XML_SECURITY_ORACLE],
    );
    in_alpine(
        'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version'
        . ' && sh tests/xml-security/Dsig/Fixture/oracle/verify-every-scheme.sh '
        . XML_SECURITY_ORACLE
        . ' && sh tests/xml-security/Enc/Fixture/oracle/decrypt-every-scheme.sh '
        . XML_SECURITY_ORACLE
        . '/enc',
        [
            'tests/xml-security/Dsig/Fixture/oracle/verify-every-scheme.sh',
            'tests/xml-security/Dsig/Fixture/keys/test-signing-certificate.pem',
            'tests/xml-security/Enc/Fixture/oracle/decrypt-every-scheme.sh',
            'tests/xml-security/Enc/Fixture/keys/test-signing-key.pem',
            XML_SECURITY_ORACLE,
        ],
    );
}

/**
 * Alpine 3.22, pinned by the digest of its index, which names the image of each platform: 3.22.6 when it was taken, on
 * 20 October 2026. The tag moves with every release of the branch, and the image is what installs the tools of the
 * oracles and runs them.
 */
const ALPINE_IMAGE = 'alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8';

/**
 * A shell command in Alpine: xmlsec1, the OpenSSL command line or Python, which the command installs itself from the
 * network, given what it reads and nothing else of the repository.
 *
 * @param list<string> $paths the files and directories the command reads (alpine_command())
 */
function in_alpine(string $command, array $paths): void
{
    run(alpine_command($command, $paths));
}

/**
 * The docker command that runs a shell command in Alpine, in /project, where each of the paths it reads is mounted
 * read-only at the place it has in the working directory, and nothing else is: the rest of the repository, the
 * secrets of apps/op/.env.local and the keys under var/ among it, is not in a container whose packages come from the
 * network at every run. A path is relative to the working directory and stays inside it once its links are resolved;
 * one that does not exist, or that a mount cannot carry, stops the task.
 *
 * @param list<string> $paths
 *
 * @return list<string>
 */
function alpine_command(string $command, array $paths): array
{
    $root = (string) realpath((string) getcwd());
    $mounts = [];
    foreach (array_unique($paths) as $path) {
        $source = realpath($path);
        if (
            $source === false
            || str_starts_with($path, '/')
            || $source !== $root && ! str_starts_with($source, $root . '/')
            || strpbrk($path . $source, ',:') !== false
        ) {
            io()->error(sprintf('%s is not a file or a directory of the working directory a container can be given.', $path));
            exit(1);
        }
        $mounts[] = '--mount';
        $mounts[] = sprintf('type=bind,source=%s,target=/project/%s,readonly', $source, $path);
    }

    return ['docker', 'run', '--rm', '-i', ...$mounts, '-w', '/project', ALPINE_IMAGE, 'sh', '-c', $command];
}
