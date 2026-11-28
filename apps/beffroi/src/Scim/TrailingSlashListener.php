<?php

declare(strict_types=1);

namespace App\Scim;

use function str_ends_with;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Spec/scim.md section 6.12: a path under the base path of SCIM that ends with a slash names no endpoint, as no
 * endpoint of RFC 7644 §3.2 does, and is answered so before the router sends a GET of it to the path without its slash.
 * While SCIM is off, nothing is refused here.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: self::PRIORITY)]
final readonly class TrailingSlashListener
{
    /**
     * Above the RouterListener (32).
     */
    public const int PRIORITY = 33;

    public function __construct(
        private ?ScimAnswers $answers = null,
    ) {
    }

    /**
     * @throws NotFoundHttpException
     */
    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if ($this->answers instanceof ScimAnswers && $this->answers->serves($request) && str_ends_with($request->getPathInfo(), '/')) {
            throw new NotFoundHttpException(ScimRoutes::NO_ENDPOINT);
        }
    }
}
