<?php

declare(strict_types=1);

/*
 * beffroi/saml against what is not this project and without the stack (spec/saml.md section 9): the metadata of the
 * service provider of a tenant read by SimpleSAMLphp's own parser (issue #778, S-39), in the image of the SimpleSAMLphp
 * 2.5.3.1 of the judge of saml2-bindings (tests/saml2-bindings/Interop/simplesamlphp/installation/), built from its
 * pinned Dockerfile when it is not there. By hand, never in the CI, as the judges of 9b are.
 */

use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\exit_code;
use function Castor\run;

/**
 * Where ServiceProviderMetadataOracleTest writes the metadata and what a reader must find in them, under the ignored
 * var/.
 */
const SAML_INTEROP_ORACLE = 'var/oracle/saml';

/**
 * The image the judge of saml2-bindings builds, SimpleSAMLphp 2.5.3.1 and its PHP, whose parser reads the metadata.
 */
const SAML_INTEROP_SIMPLESAMLPHP_IMAGE = 'saml2-bindings-simplesamlphp:2.5.3.1';

#[AsTask(
    description: 'The metadata of the service provider of a tenant read by SimpleSAMLphp 2.5.3.1\'s own parser, SAMLParser::parseDescriptorsString() and getMetadata20SP(), in the image of the judge of saml2-bindings, built if needed (spec/saml.md section 9, S-39); by hand, never in the CI: PHP_VERSION=8.5 castor saml-simplesamlphp-parser',
)]
function saml_simplesamlphp_parser(): void
{
    saml2_bindings_installed();
    foreach (glob(SAML_INTEROP_ORACLE . '/*') ?: [] as $file) {
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
            'saml',
            '--filter',
            'ServiceProviderMetadataOracleTest',
        ],
        ['SAML_SP_METADATA_ORACLE' => SAML_INTEROP_ORACLE],
    );
    if (exit_code(['docker', 'image', 'inspect', SAML_INTEROP_SIMPLESAMLPHP_IMAGE], context: context()->withQuiet()) !== 0) {
        run(['docker', 'compose', '-f', SAML2_BINDINGS_SIMPLESAMLPHP . '/installation/compose.yaml', 'build', 'idp']);
    }
    // what the script reads, mounted read-only: the script and the two files of the oracle, and nothing else
    run([
        'docker',
        'run',
        '--rm',
        '--entrypoint',
        'php',
        '-v',
        getcwd() . '/' . SAML_INTEROP_ORACLE . ':/oracle:ro',
        '-v',
        getcwd() . '/tests/saml/Interop/simplesamlphp/read-service-provider-metadata.php:/read-service-provider-metadata.php:ro',
        SAML_INTEROP_SIMPLESAMLPHP_IMAGE,
        '/read-service-provider-metadata.php',
        '/oracle',
    ]);
}
