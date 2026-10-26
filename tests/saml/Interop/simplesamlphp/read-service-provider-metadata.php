<?php

declare(strict_types=1);

/*
 * beffroi/saml, spec/saml.md section 9, S-39: the metadata of the service provider of a tenant read by SimpleSAMLphp's
 * own parser, as its metarefresh module and its identity provider read the metadata of a service provider. Run by
 * "castor saml-simplesamlphp-parser" with PHP of the image of SimpleSAMLphp 2.5.3.1 the harness of saml2-bindings
 * builds (tests/saml2-bindings/Interop/simplesamlphp/installation/), on the two files ServiceProviderMetadataOracleTest
 * wrote: the document, and what a reader must find in it. It prints what SimpleSAMLphp read and exits 1 at the first
 * difference.
 *
 * Usage: php read-service-provider-metadata.php <directory holding sp-metadata.xml and expected.json>
 */

use SimpleSAML\Metadata\SAMLParser;

require '/var/simplesamlphp/vendor/autoload.php';

$directory = $argv[1] ?? '';
$document = (string) file_get_contents($directory . '/sp-metadata.xml');
$expected = json_decode((string) file_get_contents($directory . '/expected.json'), true, 4, JSON_THROW_ON_ERROR);

$parsed = SAMLParser::parseDescriptorsString($document);
$read = [];
foreach ($parsed as $entityId => $parser) {
    $sp = $parser->getMetadata20SP();
    $idp = $parser->getMetadata20IdP();
    $read[] = [
        'entityId' => $entityId,
        'serviceProvider' => $sp !== null,
        'identityProvider' => $idp !== null,
        'AssertionConsumerService' => $sp['AssertionConsumerService'] ?? null,
        'SingleLogoutService' => $sp['SingleLogoutService'] ?? null,
        'NameIDFormat' => $sp['NameIDFormat'] ?? null,
        'validate.authnrequest' => $sp['validate.authnrequest'] ?? null,
        'saml20.sign.assertion' => $sp['saml20.sign.assertion'] ?? null,
        'keys' => $sp['keys'] ?? null,
    ];
}
echo json_encode($read, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

$keys = [];
foreach ($expected['certificates'] as $certificate) {
    $keys[] = [
        'encryption' => false,
        'signing' => true,
        'type' => 'X509Certificate',
        'X509Certificate' => $certificate,
    ];
}
$checks = [
    'one entity, the one of the metadata' => [[$expected['entityId']], array_column($read, 'entityId')],
    'a service provider role' => [true, $read[0]['serviceProvider'] ?? null],
    'no identity provider role' => [false, $read[0]['identityProvider'] ?? null],
    'one assertion consumer service, on HTTP-POST, of index 0' => [
        [[
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => $expected['assertionConsumerService'],
            'index' => 0,
        ]],
        array_map(
            static fn (array $endpoint): array => array_intersect_key($endpoint, ['Binding' => true, 'Location' => true, 'index' => true]),
            $read[0]['AssertionConsumerService'] ?? [],
        ),
    ],
    'no single logout service' => [[], $read[0]['SingleLogoutService'] ?? null],
    'no NameID format' => [null, $read[0]['NameIDFormat'] ?? null],
    'the requests signed (AuthnRequestsSigned)' => [true, $read[0]['validate.authnrequest'] ?? null],
    'the assertions wanted signed (WantAssertionsSigned)' => [true, $read[0]['saml20.sign.assertion'] ?? null],
    'a key for signing per certificate, in creation order' => [$keys, $read[0]['keys'] ?? null],
];
$failed = false;
foreach ($checks as $what => [$want, $got]) {
    $same = $want === $got;
    $failed = $failed || ! $same;
    printf("%s %s\n", $same ? 'ok    ' : 'FAILED', $what);
}
exit($failed ? 1 : 0);
