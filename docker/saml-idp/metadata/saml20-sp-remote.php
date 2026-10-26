<?php

// The service provider of the stack, as its metadata publish it for this identity provider: fetched over https from the
// provider at every request, as SimpleSAMLphp parses its metadata at every request, and read by its own parser. The
// provider serves the metadata of its service provider to each upstream identity provider at a URL of its own, whose
// last segment is the entity ID of that identity provider in the base64url of RFC 4648 section 5, without padding
// (issue #787), so that each is given the certificates meant for it alone. The root certificate of the stack (copied
// out of the op container into var/saml-idp/ by "castor saml-idp") is the one that verifies the connection, and nothing
// about it is relaxed: no http, no unverified peer.
//
// While the provider serves no such metadata, before the service provider of the tenant is enabled and this identity
// provider declared, nothing is read, the reason goes to the log, and the identity provider knows no service provider:
// its own metadata are served all the same.
//
// What the metadata of the service provider say is what this identity provider does with it: AuthnRequestsSigned
// becomes validate.authnrequest (SAMLParser::getMetadata20SP()), under which an AuthnRequest without a signature is
// refused. They list no NameID format: the one the NameID is given in is the persistent one the NameIDPolicy of the
// request asks for (issue #783), which the identity provider draws (saml20-idp-hosted.php).
//
// The assertion is encrypted when the file /saml-idp/assertion-encryption, which "castor saml-idp" writes before a
// journey, says "yes": for the first certificate for encryption of these metadata, the one the provider gives this
// identity provider alone (spec/saml.md S-64, S-65), its session key under rsa-oaep-mgf1p and its content under
// aes128-cbc, the one content algorithm SimpleSAMLphp 2.5.3.1 encrypts for a certificate with (EncryptedAssertion::
// setAssertion() of simplesamlphp/saml2), which the provider opens only under the verified signature of the response
// (decision 0013), signed here (saml20-idp-hosted.php).
use SimpleSAML\Metadata\SAMLParser;

// Variables and not constants: SimpleSAMLphp includes this file once per lookup.
$beffroiIdentityProvider = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';
$beffroiMetadataUrl = 'https://op.localhost/saml/sp/metadata/' . rtrim(strtr(base64_encode($beffroiIdentityProvider), '+/', '-_'), '=');
$beffroiCa = '/saml-idp/caddy-root.crt';

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
    error_log('the metadata of the service provider could not be read from ' . $beffroiMetadataUrl);

    return;
}

foreach (SAMLParser::parseDescriptorsString($document) as $entityId => $parser) {
    $sp = $parser->getMetadata20SP();
    if ($sp !== null) {
        $sp['assertion.encryption'] = is_file('/saml-idp/assertion-encryption')
            && trim((string) file_get_contents('/saml-idp/assertion-encryption')) === 'yes';
        $metadata[$entityId] = $sp;
    }
}
