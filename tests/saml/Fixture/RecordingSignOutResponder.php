<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Port\SignOutResponderInterface;

/**
 * A responder that keeps what it was asked to write, and answers with a URL naming where it goes; or one whose key
 * cannot be opened, which then neither opens nor answers, as the responder of a tenant without its key does not.
 */
final class RecordingSignOutResponder implements SignOutResponderInterface
{
    public private(set) ?SignOutResponse $response = null;

    public function __construct(
        private readonly KeyNotFoundException|KmsUnavailableException|null $unopened = null,
    ) {
    }

    public function open(Tenant $tenant): void
    {
        if ($this->unopened !== null) {
            throw $this->unopened;
        }
    }

    public function answer(Tenant $tenant, SignOutResponse $response): RedirectedMessage
    {
        if ($this->unopened !== null) {
            throw $this->unopened;
        }
        $this->response = $response;

        return new RedirectedMessage($response->requester->answerLocation . '?SAMLResponse=answered');
    }
}
