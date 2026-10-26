<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Throwable;

/**
 * A response of an upstream identity provider that signs nobody in, and what the browser is answered instead
 * (beffroi/saml S-53 to S-59): the page of a refusal, the page of an interaction that cannot be resumed, the request
 * sent once more with ForceAuthn, or the error login_required at the redirection URI of the client. The answer is
 * decided where the response is read, which knows the interaction and the request remembered, and handed to the
 * firewall that renders it.
 */
final class UpstreamLoginRefusedException extends AuthenticationException
{
    /**
     * @param LoginFailure|null $failure what the audit trail is told of it (S-53), null when it is no refused login:
     *                                   the request sent once more, an answer to the client, an interaction gone
     */
    public function __construct(
        public readonly Response $answer,
        string $message = 'The response of the upstream identity provider signs nobody in.',
        ?Throwable $previous = null,
        public readonly ?LoginFailure $failure = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
