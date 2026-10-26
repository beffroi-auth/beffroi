<?php

// What the service provider "beffroi" holds, as JSON, mounted into public/ by compose.yaml: the proof, for the judge,
// that it read the metadata of the identity provider (?idp: the entity, its single sign-on and single logout services,
// its keys by the SHA-256 of their DER) and, without it, that it accepted a response and with which values (the
// session: the identity provider, the NameID, the session index, the attributes it received).
require '/var/simplesamlphp/src/_autoload.php';

header('Content-Type: application/json');
$flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES;

if (isset($_GET['idp'])) {
    $entityId = \SimpleSAML\Configuration::getConfig('authsources.php')->getArray('beffroi')['idp'];
    $idp = \SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler()->getMetaDataConfig($entityId, 'saml20-idp-remote');
    echo json_encode([
        'entityId' => $idp->getString('entityid'),
        'singleSignOnService' => $idp->getArray('SingleSignOnService'),
        'singleLogoutService' => $idp->getOptionalArray('SingleLogoutService', []),
        'signAuthnRequest' => $idp->getOptionalBoolean('sign.authnrequest', false),
        'keys' => array_map(
            static fn (array $key): array => [
                'use' => ['signing' => $key['signing'] ?? false, 'encryption' => $key['encryption'] ?? false],
                'sha256' => hash('sha256', (string) base64_decode((string) ($key['X509Certificate'] ?? ''), true)),
            ],
            $idp->getOptionalArray('keys', []),
        ),
    ], $flags);

    return;
}

// ?as= names the service provider whose session is read, "beffroi" unless it is "beffroi-encrypted" (issue #733)
$as = new \SimpleSAML\Auth\Simple(($_GET['as'] ?? '') === 'beffroi-encrypted' ? 'beffroi-encrypted' : 'beffroi');
if (!$as->isAuthenticated()) {
    http_response_code(401);
    echo json_encode(['authenticated' => false]);

    return;
}
$nameId = $as->getAuthData('saml:sp:NameID');
echo json_encode([
    'authenticated' => true,
    'idp' => $as->getAuthData('saml:sp:IdP'),
    'nameId' => $nameId instanceof \SAML2\XML\saml\NameID
        ? ['value' => $nameId->getValue(), 'format' => $nameId->getFormat(), 'spNameQualifier' => $nameId->getSPNameQualifier()]
        : null,
    'sessionIndex' => $as->getAuthData('saml:sp:SessionIndex'),
    'attributes' => $as->getAttributes(),
], $flags);
