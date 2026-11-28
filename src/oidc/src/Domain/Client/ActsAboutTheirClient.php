<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Domain\Consent\ConsentActs;
use Beffroi\Oidc\Domain\EndSession\SessionEndActs;

/**
 * The acts of a person whose client is what they are about, an application allowed, taken back or signed out, and not
 * the one their author acted through: the page and the archive of the person name it whoever did the act.
 */
final class ActsAboutTheirClient
{
    /**
     * @var list<string>
     */
    public const array NAMES = [
        ...ConsentActs::NAMES,
        ...SessionEndActs::NAMES,
    ];
}
