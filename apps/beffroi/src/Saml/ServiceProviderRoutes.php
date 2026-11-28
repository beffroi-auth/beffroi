<?php

declare(strict_types=1);

namespace App\Saml;

final class ServiceProviderRoutes
{
    public const string METADATA = 'beffroi_protocol_saml_service_provider_metadata';

    public const string METADATA_PATH = '/saml/sp/metadata';

    public const string METADATA_FOR_IDENTITY_PROVIDER = 'beffroi_protocol_saml_sp_metadata_for_identity_provider';

    public const string METADATA_FOR_IDENTITY_PROVIDER_PATH = '/saml/sp/metadata/{identityProvider}';

    public const string ASSERTION_CONSUMER_SERVICE = 'beffroi_interaction_saml_assertion_consumer_service';

    public const string ASSERTION_CONSUMER_SERVICE_PATH = '/saml/sp/acs';

    public const string UPSTREAM_SIGN_ON = 'beffroi_interaction_saml_upstream_sign_on';

    public const string UPSTREAM_SIGN_ON_PATH = '/saml/sp/sign-on';

    public const string IDENTITY_PROVIDER_PARAMETER = 'identity_provider';

    public const string REFERENCE_PARAMETER = 'reference';

    private function __construct()
    {
    }
}
