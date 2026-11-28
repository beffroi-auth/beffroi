<?php

declare(strict_types=1);

namespace App\Credential;

/**
 * Decision 0049: a channel that tells a change of a channel of a person to the one it replaced, which no longer reaches
 * her once the change is written; told only the changes that replaced a channel of its claim.
 */
interface ReplacedChannelInterface extends CredentialChangeChannelInterface
{
    /**
     * @return string the claim of the channel it reaches once replaced, OIDC Core §5.1
     */
    public function claim(): string;
}
