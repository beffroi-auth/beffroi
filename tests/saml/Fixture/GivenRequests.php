<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Port\AuthnRequestReceiverInterface;

/**
 * A receiver that accepts whatever arrives as the request a test gives it, over either binding.
 */
final readonly class GivenRequests implements AuthnRequestReceiverInterface
{
    public function __construct(
        private SignOnRequest $request,
    ) {
    }

    public function redirect(Tenant $tenant, string $queryString): SignOnRequest
    {
        return $this->request;
    }

    public function post(Tenant $tenant, array $fields): SignOnRequest
    {
        return $this->request;
    }
}
