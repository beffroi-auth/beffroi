<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Port\SignOnResponderInterface;

/**
 * A responder that keeps what it was asked to write, and answers with a form naming it.
 */
final class RecordingResponder implements SignOnResponderInterface
{
    public private(set) ?SignOnResponse $response = null;

    public private(set) ?SignOnFailure $failure = null;

    public function success(Tenant $tenant, SignOnResponse $response): PostedForm
    {
        $this->response = $response;

        return new PostedForm($response->request->assertionConsumerService, ['SAMLResponse' => 'success']);
    }

    public function failure(Tenant $tenant, SignOnFailure $failure): PostedForm
    {
        $this->failure = $failure;

        return new PostedForm($failure->request->assertionConsumerService, ['SAMLResponse' => 'failure']);
    }
}
