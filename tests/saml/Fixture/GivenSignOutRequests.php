<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Port\LogoutMessageReceiverInterface;

/**
 * A receiver that accepts whatever arrives as the logout message a test gives it, a request or the answer of a chain,
 * over either binding, and counts the messages it was handed, each of which the receiver of the bundle would have
 * remembered.
 */
final class GivenSignOutRequests implements LogoutMessageReceiverInterface
{
    public private(set) int $received = 0;

    public function __construct(
        private readonly SignOutRequest|SignOutAnswer $message,
    ) {
    }

    public function redirect(Tenant $tenant, string $queryString, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer
    {
        ++$this->received;

        return $this->message;
    }

    public function post(Tenant $tenant, array $fields, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer
    {
        ++$this->received;

        return $this->message;
    }
}
