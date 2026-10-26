<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Domain\Metadata\PublishedMetadata;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The metadata of the SAML identity provider of the tenant (beffroi/saml, spec/saml.md section 6.1): its entity ID,
 * the certificate of each of its signing keys in service and its endpoints. A tenant that holds no SAML key has none to
 * serve, and neither has any tenant of a deployment that does not enable "beffroi.saml.identity_provider", which wires
 * no handler (S-41): the SAML key its service provider keeps in service publishes no metadata of an identity provider,
 * and the key a tenant drew while either role was enabled is dormant once both are off, read by nothing
 * (DormantKeyAlgorithms).
 */
#[AsController]
final readonly class SamlMetadataController
{
    public function __construct(
        private TenantProvider $tenants,
        private ?IdentityProviderMetadataHandler $handler = null,
    ) {
    }

    #[Route(IdentityProviderRoutes::METADATA_PATH, name: IdentityProviderRoutes::METADATA, methods: ['GET'])]
    public function __invoke(): Response
    {
        if (! $this->handler instanceof IdentityProviderMetadataHandler) {
            throw new NotFoundHttpException('This tenant serves no SAML identity provider.');
        }
        try {
            $metadata = $this->handler->handle($this->tenants->provide());
        } catch (KeyNotFoundException $exception) {
            throw new NotFoundHttpException('This tenant serves no SAML identity provider.', $exception);
        }

        return new Response($metadata->document, Response::HTTP_OK, [
            'Content-Type' => PublishedMetadata::CONTENT_TYPE,
        ] + $metadata->headers);
    }
}
