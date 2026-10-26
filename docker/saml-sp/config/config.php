<?php

// The configuration SimpleSAMLphp 2.5.3.1 distributes, then the settings of the service provider of the judge
// (issue #732) that differ from it. The service provider answers on https://saml-sp.localhost, through the Caddy of
// the op container, so the base URL is given whole: it is what the entity ID, the assertion consumer service and every
// URL of its metadata are built from.
require '/var/simplesamlphp/config-dist/config.php.dist';

$config['baseurlpath'] = 'https://saml-sp.localhost/simplesaml/';
$config['secretsalt'] = 'the development service provider of the judge, not a secret';
$config['logging.handler'] = 'errorlog';
// The certificate of the service provider, written by "castor saml-sp" under var/saml-sp/ and mounted here; its key,
// beside it, is read from the copy the command of the service makes (compose.yaml, authsources.php).
$config['certdir'] = '/saml-sp/';
