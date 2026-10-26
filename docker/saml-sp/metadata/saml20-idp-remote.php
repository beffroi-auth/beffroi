<?php

// The identity provider of the stack, as its metadata publish it: fetched over https from the provider at every
// request, as SimpleSAMLphp parses its metadata at every request, and read by its own parser. The root certificate of
// the internal CA of Caddy is the one that verifies the connection (copied out of the op container into var/saml-sp/ by
// "castor saml-sp"), and nothing about the connection is relaxed: no http, no unverified peer.
//
// SimpleSAMLphp sends its request to the HTTP-Redirect service whenever the metadata list one, so the judge could never
// play HTTP-POST from the metadata as the provider publishes them (both bindings, spec/saml.md section 6.1). The file
// /saml-sp/sso-binding, which "castor saml-sp" writes before each request, narrows the single sign-on service the
// service provider sees to that binding, and only that: the document, its keys and its other services are the provider's.
use SimpleSAML\Metadata\SAMLParser;

// Variables and not constants: SimpleSAMLphp includes this file once per lookup.
$beffroiMetadataUrl = 'https://op.localhost/saml/metadata';
$beffroiCa = '/saml-sp/caddy-root.crt';

$document = file_get_contents($beffroiMetadataUrl, false, stream_context_create([
    'http' => [
        'method' => 'GET',
        'header' => "Accept: application/samlmetadata+xml\r\n",
        'timeout' => 5,
        'follow_location' => 0,
    ],
    'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'cafile' => $beffroiCa,
    ],
]));
if (!is_string($document) || $document === '') {
    error_log('the metadata of the identity provider could not be read from ' . $beffroiMetadataUrl);

    return;
}

$only = match (is_file('/saml-sp/sso-binding') ? trim((string) file_get_contents('/saml-sp/sso-binding')) : '') {
    'post' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    'redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    default => null,
};

foreach (SAMLParser::parseDescriptorsString($document) as $entityId => $parser) {
    $idp = $parser->getMetadata20IdP();
    if ($idp === null) {
        continue;
    }
    if ($only !== null) {
        $idp['SingleSignOnService'] = array_values(array_filter(
            $idp['SingleSignOnService'] ?? [],
            static fn (array $endpoint): bool => ($endpoint['Binding'] ?? null) === $only,
        ));
    }
    $metadata[$entityId] = $idp;
}
