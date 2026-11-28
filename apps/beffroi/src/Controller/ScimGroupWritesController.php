<?php

declare(strict_types=1);

namespace App\Controller;

use App\Scim\ScimEndpoints;
use App\Scim\ScimRoutes;
use Beffroi\Scim\Domain\Answer\ScimAnswer;
use Beffroi\Scim\Domain\Error\NotServed;
use Beffroi\Scim\Domain\Schema\GroupSchema;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Spec/scim.md section 5.1, section 6.1 steps 4 and 5: the writes of the Group resources, their body read under the
 * schema of the endpoint before the operation, which the provider does not serve.
 */
#[AsController]
final readonly class ScimGroupWritesController
{
    public function __construct(
        private ?ScimEndpoints $scim = null,
    ) {
    }

    #[Route(ScimRoutes::BASE_PATH . '/Groups', name: 'beffroi_protocol_scim_group_creation', methods: ['POST'])]
    #[Route(ScimRoutes::BASE_PATH . '/Groups/{id}', name: 'beffroi_protocol_scim_group_replacement', methods: ['PUT'])]
    #[Route(ScimRoutes::BASE_PATH . '/Groups/{id}', name: 'beffroi_protocol_scim_group_patch', methods: ['PATCH'])]
    public function __invoke(Request $request): Response
    {
        if (! $this->scim instanceof ScimEndpoints) {
            throw new NotFoundHttpException(ScimEndpoints::OFF);
        }

        return $this->scim->write($request, new GroupSchema(), static fn (): ScimAnswer => ScimAnswer::error(NotServed::error()));
    }
}
