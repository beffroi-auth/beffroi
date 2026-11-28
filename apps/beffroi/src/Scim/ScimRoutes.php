<?php

declare(strict_types=1);

namespace App\Scim;

/**
 * spec/scim.md section 5.1: the base path of the module ends in the version, right before the endpoint of a resource
 * (RFC 7644 §3.13), and the name of each route carries the protocol plane.
 */
final class ScimRoutes
{
    public const string BASE_PATH = '/scim/v2';

    public const string USERS = 'beffroi_protocol_scim_users';

    public const string NO_ENDPOINT = 'No endpoint of SCIM is served at this path.';

    private function __construct()
    {
    }
}
