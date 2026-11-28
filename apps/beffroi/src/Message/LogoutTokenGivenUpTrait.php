<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use DateTimeImmutable;

/**
 * Back-Channel Logout 1.0 §2.8
 *
 * @phpstan-require-implements LogoutTokenNotification
 */
trait LogoutTokenGivenUpTrait
{
    public function givenUp(DateTimeImmutable $at, string $reason): LogoutTokenGivenUp
    {
        return new LogoutTokenGivenUp(
            $at,
            $this->tenant,
            $this->context,
            $this->clientId,
            $this->subject,
            $this->sessionId,
            $reason,
            $this->author,
        );
    }
}
