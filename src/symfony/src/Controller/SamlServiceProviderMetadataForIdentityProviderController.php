<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Saml\IdentityProviderSegment;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\Metadata\ServiceProviderMetadataHandler;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The metadata of the SAML service provider of the tenant given to one upstream identity provider (beffroi/saml,
 * spec/saml.md S-65, section 6.12): those of the URL of the entity ID, with the certificate of each key that provider
 * encrypts for, the newest first, and of no other provider. The provider is named by the last segment of the URL, its
 * entity ID in base64url (IdentityProviderSegment).
 *
 * A deployment that does not enable "beffroi.saml.service_provider" serves none (S-41); neither has a segment that
 * names no entity ID, nor a provider for which the tenant holds no key in service, the key of a provider the deployment
 * does not declare being read past (S-64).
 */
#[AsController]
final readonly class SamlServiceProviderMetadataForIdentityProviderController
{
    public function __construct(
        private TenantProvider $tenants,
        private ?ServiceProviderMetadataHandler $handler = null,
    ) {
    }

    #[Route(
        ServiceProviderRoutes::METADATA_FOR_IDENTITY_PROVIDER_PATH,
        name: ServiceProviderRoutes::METADATA_FOR_IDENTITY_PROVIDER,
        requirements: [
            'identityProvider' => IdentityProviderSegment::REQUIREMENT,
        ],
        methods: ['GET'],
    )]
    public function __invoke(string $identityProvider): Response
    {
        if (! $this->handler instanceof ServiceProviderMetadataHandler) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        }
        $entityId = IdentityProviderSegment::entityIdOf($identityProvider);
        if ($entityId === null) {
            throw new NotFoundHttpException('The service provider of this tenant gives no metadata to this identity provider.');
        }
        try {
            $metadata = $this->handler->handleFor($this->tenants->provide(), $entityId);
        } catch (KeyNotFoundException $exception) {
            throw new NotFoundHttpException('The service provider of this tenant gives no metadata to this identity provider.', $exception);
        }

        return new Response($metadata->document, Response::HTTP_OK, [
            'Content-Type' => PublishedMetadata::CONTENT_TYPE,
        ] + $metadata->headers);
    }
}
