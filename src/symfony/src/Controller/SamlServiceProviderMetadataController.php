<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The metadata of the SAML service provider of the tenant (beffroi/saml, spec/saml.md section 6.9): its entity ID, the
 * certificate of each SAML key in service and its assertion consumer service, what an upstream identity provider is
 * configured from. A deployment that does not enable "beffroi.saml.service_provider" wires no handler and serves none,
 * whatever keys its tenant holds (S-41); neither has a tenant that holds no SAML key.
 */
#[AsController]
final readonly class SamlServiceProviderMetadataController
{
    public function __construct(
        private TenantProvider $tenants,
        private ?ServiceProviderMetadataHandler $handler = null,
    ) {
    }

    #[Route(ServiceProviderRoutes::METADATA_PATH, name: ServiceProviderRoutes::METADATA, methods: ['GET'])]
    public function __invoke(): Response
    {
        if (! $this->handler instanceof ServiceProviderMetadataHandler) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        }
        try {
            $metadata = $this->handler->handle($this->tenants->provide());
        } catch (KeyNotFoundException $exception) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.', $exception);
        }

        return new Response($metadata->document, Response::HTTP_OK, [
            'Content-Type' => PublishedMetadata::CONTENT_TYPE,
        ] + $metadata->headers);
    }
}
