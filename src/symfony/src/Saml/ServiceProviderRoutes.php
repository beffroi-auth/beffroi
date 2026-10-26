<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

/**
 * The routes of the SAML service provider of a tenant, their names and their paths under the prefix the bundle is
 * mounted at, which is the path of the issuer (spec/saml.md sections 5.6, 5.8 and 5.10). The metadata names two of
 * them: the assertion consumer service, whose controller takes its route from here and whose URL the router generates
 * for the metadata, so that what the metadata announce is where it answers (S-39, S-52). The third, named by no metadata, is where an interaction
 * of the browser starts a sign-on at an upstream identity provider (S-51); the fourth serves the metadata given to one
 * upstream identity provider, its certificates for encryption among them (S-65).
 *
 * The metadata is read server to server, the protocol plane; the assertion consumer service is where the browser posts
 * a response, and the sign-on where it is sent from an interaction, the plane of the interactions (architecture §5.2).
 */
final class ServiceProviderRoutes
{
    public const string METADATA = 'beffroi_protocol_saml_service_provider_metadata';

    public const string METADATA_PATH = '/saml/sp/metadata';

    /**
     * The metadata given to one upstream identity provider, with the certificate of each key it encrypts for, its last
     * segment the entity ID of the provider in base64url (spec/saml.md S-65, IdentityProviderSegment): server to
     * server, as the metadata at the URL of the entity ID are.
     */
    public const string METADATA_FOR_IDENTITY_PROVIDER = 'beffroi_protocol_saml_service_provider_metadata_for_identity_provider';

    public const string METADATA_FOR_IDENTITY_PROVIDER_PATH = '/saml/sp/metadata/{identityProvider}';

    public const string ASSERTION_CONSUMER_SERVICE = 'beffroi_interaction_saml_assertion_consumer_service';

    public const string ASSERTION_CONSUMER_SERVICE_PATH = '/saml/sp/acs';

    /**
     * Where an interaction of the browser starts a sign-on at an upstream identity provider (spec/saml.md S-51).
     */
    public const string UPSTREAM_SIGN_ON = 'beffroi_interaction_saml_upstream_sign_on';

    public const string UPSTREAM_SIGN_ON_PATH = '/saml/sp/sign-on';

    /**
     * The parameter of that route that names the provider, its entity ID; the interaction is named as on every page of
     * an interaction (AuthorizationResponder::INTERACTION_PARAMETER).
     */
    public const string IDENTITY_PROVIDER_PARAMETER = 'identity_provider';

    /**
     * The parameter of that route that carries the one-time reference the login page drew for that sign-on
     * (UpstreamSignOnReferences, spec/saml.md S-51).
     */
    public const string REFERENCE_PARAMETER = 'reference';

    private function __construct()
    {
    }
}
