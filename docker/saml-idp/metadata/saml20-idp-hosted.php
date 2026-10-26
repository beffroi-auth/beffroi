<?php

// The hosted identity provider of the judge (issue #788), the upstream identity provider the service provider of the
// stack federates to: its entity ID is the URL of its metadata, as SimpleSAMLphp names one by default. What differs
// from the defaults of SimpleSAMLphp 2.5.3.1, each with its reason:
//
// - its single sign-on service published for HTTP-Redirect and for HTTP-POST, where SimpleSAMLphp publishes
//   HTTP-Redirect alone. The provider sends its AuthnRequest over HTTP-Redirect whenever the metadata list it
//   (spec/saml.md S-48), so the file /saml-idp/sso-binding, which "castor saml-idp" writes before it captures the
//   metadata the provider reads, narrows what is published to one binding, "redirect" or "post", and only that;
// - a persistent NameID, drawn by the saml:PersistentNameID filter from the "uid" of the person, the secret salt and
//   both entity IDs: the same person at the same service provider gets the same one at every sign-in, which is what
//   names her to the provider. Its format is the one published, and the one SimpleSAMLphp gives a request that asks
//   for none; without the filter it would give a transient one whatever it published;
// - carol refused once she has signed in, by a filter that throws the error of SimpleSAMLphp's SAML module with the
//   status Responder and AuthnFailed: thrown at her first login, it is an error page of SimpleSAMLphp, the login having
//   no request to answer by then; thrown when a request finds her signed in, SimpleSAMLphp answers that request with a
//   Response of that status and no assertion (IdP::handleAuthenticationRequest(), SAML2::handleAuthError()), the
//   failure the provider answers its client access_denied for (spec/saml.md S-58);
// - the response and its assertion signed, both, as SimpleSAMLphp does by default, said here since the provider
//   verifies both;
// - the attributes named by their plain name, "mail", "givenName", "sn", "groups", the names the declaration of this
//   identity provider maps, under the basic name format, where SimpleSAMLphp would announce the URI one;
// - its metadata signed with its own key, under the certificate they publish: a signature xmlsec1 and the model
//   verify, though the provider reads the metadata by their channel (the metadata carry no validUntil, which
//   SimpleSAMLphp 2.5.3.1 does not write for a hosted identity provider).
//
// Its key is the copy of var/saml-idp/idp.pem the command of the service gives www-data (compose.yaml), the file itself
// being its owner's alone on the machine; its certificate is var/saml-idp/idp.crt, under the certdir of config.php.
$beffroiBindings = [
    'redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    'post' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
];
$beffroiOnly = is_file('/saml-idp/sso-binding') ? trim((string) file_get_contents('/saml-idp/sso-binding')) : '';

$metadata['https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata'] = [
    'host' => '__DEFAULT__',
    'privatekey' => '/run/saml-idp/idp.pem',
    'certificate' => 'idp.crt',
    'auth' => 'lab-people',
    'SingleSignOnServiceBinding' => isset($beffroiBindings[$beffroiOnly]) ? [$beffroiBindings[$beffroiOnly]] : array_values($beffroiBindings),
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'authproc' => [
        10 => [
            'class' => 'saml:PersistentNameID',
            'identifyingAttribute' => 'uid',
        ],
        20 => [
            'class' => 'core:PHP',
            'code' => 'if (($attributes["uid"][0] ?? null) === "carol") { throw new \SimpleSAML\Module\saml\Error("urn:oasis:names:tc:SAML:2.0:status:Responder", "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", "The laboratory identity provider refuses carol."); }',
        ],
    ],
    'saml20.sign.response' => true,
    'saml20.sign.assertion' => true,
    'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
    'metadata.sign.enable' => true,
    'metadata.sign.privatekey' => '/run/saml-idp/idp.pem',
    'metadata.sign.certificate' => 'idp.crt',
];
