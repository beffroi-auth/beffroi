<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Security\UpstreamAssertionAuthenticator;
use Beffroi\Saml\Application\Upstream\AssertionConsumerService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The route of the assertion consumer service of the service provider of the tenant (beffroi/saml, spec/saml.md S-52),
 * whose URL its metadata and its requests state as the router generates it. What reads a response is the login of the
 * firewall, UpstreamAssertionAuthenticator, which answers the post itself; what reaches this action is the post that
 * login declines: a post from another site that came without the session cookie, posted again from the provider's own
 * origin (S-28), a body that is not a form, refused with 415, or a post from another site the browser would not carry
 * back as it came, which nothing can read the request it answers for. A deployment that does not enable the service
 * provider answers 404, as at the metadata of the role (S-41).
 */
#[AsController]
final readonly class SamlAssertionConsumerServiceController
{
    public function __construct(
        private InteractionPages $pages,
        private CrossSitePost $crossSitePost,
        private ?AssertionConsumerService $consumer = null,
    ) {
    }

    #[Route(ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE_PATH, name: ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        if (! $this->consumer instanceof AssertionConsumerService) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        }
        if (! CrossSitePost::isAForm($request)) {
            return $this->pages->error(
                Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                UpstreamAssertionAuthenticator::REFUSED,
                'A response posted to the assertion consumer service is a form, application/x-www-form-urlencoded (spec/saml.md S-52).',
            );
        }

        return (
            $this->crossSitePost->postAgain($request) ?? $this->pages->error(
                Response::HTTP_BAD_REQUEST,
                UpstreamAssertionAuthenticator::REFUSED,
                'The response answers no request this browser remembers (spec/saml.md S-53).',
            )
        );
    }
}
