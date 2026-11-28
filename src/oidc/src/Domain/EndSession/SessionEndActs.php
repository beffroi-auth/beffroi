<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;

/**
 * The acts of the protocol at the end of a session of a person, which the page of their acts lists whoever ended it.
 */
final class SessionEndActs
{
    /**
     * @var list<string>
     */
    public const array NAMES = [
        SessionTokensRevoked::NAME,
    ];
}
