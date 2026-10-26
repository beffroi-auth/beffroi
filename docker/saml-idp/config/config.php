<?php

// The configuration SimpleSAMLphp 2.5.3.1 distributes, then the settings of the identity provider of the judge
// (issue #788) that differ from it. The identity provider answers on https://saml-idp.localhost, through the Caddy of
// the op container, so the base URL is given whole: it is what the entity ID, the single sign-on service and every URL
// of its metadata are built from, and the reader of metadata of the provider refuses an endpoint in plain http.
require '/var/simplesamlphp/config-dist/config.php.dist';

$config['baseurlpath'] = 'https://saml-idp.localhost/simplesaml/';
$config['secretsalt'] = 'the development identity provider of the judge, not a secret';
$config['logging.handler'] = 'errorlog';
$config['enable.saml20-idp'] = true;
$config['module.enable']['exampleauth'] = true;
// The certificate of the identity provider, written by "castor saml-idp" under var/saml-idp/ and mounted here; its
// key, beside it, is read from the copy the command of the service makes (compose.yaml, metadata/saml20-idp-hosted.php).
$config['certdir'] = '/saml-idp/';
