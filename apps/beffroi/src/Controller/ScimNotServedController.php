<?php

declare(strict_types=1);

namespace App\Controller;

use App\Scim\ScimEndpoints;
use App\Scim\ScimRoutes;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Spec/scim.md section 5.1, section 8: the operations of SCIM that read no body, which the provider does not serve, and
 * the endpoints of section 8, which it never serves. A search by POST under an endpoint is matched before the route of
 * an identifier, whose path would take ".search" for one.
 */
#[AsController]
final readonly class ScimNotServedController
{
    public function __construct(
        private ?ScimEndpoints $scim = null,
    ) {
    }

    #[Route(ScimRoutes::BASE_PATH . '/Users', name: ScimRoutes::USERS, methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Users/{id}', name: 'beffroi_protocol_scim_user', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Users/{id}', name: 'beffroi_protocol_scim_user_deletion', methods: ['DELETE'])]
    #[Route(ScimRoutes::BASE_PATH . '/Groups', name: 'beffroi_protocol_scim_groups', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Groups/{id}', name: 'beffroi_protocol_scim_group', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Groups/{id}', name: 'beffroi_protocol_scim_group_deletion', methods: ['DELETE'])]
    #[Route(ScimRoutes::BASE_PATH . '/ServiceProviderConfig', name: 'beffroi_protocol_scim_service_provider_config', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/ResourceTypes', name: 'beffroi_protocol_scim_resource_types', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/ResourceTypes/{name}', name: 'beffroi_protocol_scim_resource_type', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Schemas', name: 'beffroi_protocol_scim_schemas', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Schemas/{urn}', name: 'beffroi_protocol_scim_schema', methods: ['GET'])]
    #[Route(ScimRoutes::BASE_PATH . '/Bulk', name: 'beffroi_protocol_scim_bulk')]
    #[Route(ScimRoutes::BASE_PATH . '/.search', name: 'beffroi_protocol_scim_search')]
    #[Route(ScimRoutes::BASE_PATH . '/Users/.search', name: 'beffroi_protocol_scim_user_search', priority: 1)]
    #[Route(ScimRoutes::BASE_PATH . '/Groups/.search', name: 'beffroi_protocol_scim_group_search', priority: 1)]
    #[Route(ScimRoutes::BASE_PATH . '/Me', name: 'beffroi_protocol_scim_me')]
    public function __invoke(): Response
    {
        if (! $this->scim instanceof ScimEndpoints) {
            throw new NotFoundHttpException(ScimEndpoints::OFF);
        }

        return $this->scim->notServed();
    }
}
