<?php

// The authentication sources SimpleSAMLphp 2.5.3.1 distributes, and the one the judge plays: the service provider
// "beffroi", given its entity ID, the provider of the stack, its own signing pair (the certificate of its metadata, for
// the signature of its requests and the key an assertion is encrypted for) and signed requests in both bindings;
// and "beffroi-encrypted", the same demanding its assertion encrypted. The identity provider is the entity of the
// metadata the stack serves; where its metadata come from, and how they are read, is metadata/saml20-idp-remote.php.
require '/var/simplesamlphp/config-dist/authsources.php.dist';

$config['beffroi'] = [
    'saml:SP',
    'entityID' => 'https://saml-sp.localhost/simplesaml/module.php/saml/sp/metadata/beffroi',
    'idp' => 'https://op.localhost/saml/metadata',
    // the copy of var/saml-sp/sp.pem the command of the service gives www-data (compose.yaml), the file itself being
    // its owner's alone on the machine
    'privatekey' => '/run/saml-sp/sp.pem',
    'certificate' => 'sp.crt',
    'sign.authnrequest' => true,
    'sign.logout' => true,
    'validate.logout' => true,
];

// The same service provider demanding its assertion encrypted (issue #733, spec/saml.md S-19 to S-21): another entity,
// so that the provider holds a declaration of each, and "assertion.encryption", with which SimpleSAMLphp refuses an
// assertion in clear ("Received unencrypted assertion, but encryption was enabled.") and decrypts the other with the
// key of its metadata, the pair above.
$config['beffroi-encrypted'] = array_replace($config['beffroi'], [
    'entityID' => 'https://saml-sp.localhost/simplesaml/module.php/saml/sp/metadata/beffroi-encrypted',
    'assertion.encryption' => true,
]);
