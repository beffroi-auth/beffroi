<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

/**
 * The page of this provider a login waits for, as LoginTarget remembered it (architecture §5.4): a route of this
 * provider and the parameters our own code wrote into it, never what a request carried. What the sign-on at an upstream
 * provider remembers of the login it serves when no interaction does (beffroi/saml S-50, S-51), so that the answer of
 * that provider brings the browser back to this page and not to whichever page asks for a login next, and the step-up
 * it asked for, which the assertion consumer service holds the answer to (S-59).
 */
final readonly class WaitingPage
{
    /**
     * @param string $route a route of this provider
     * @param array<string, string> $parameters what our own code wrote into it
     * @param StepUpOffer|null $stepUp what the page asked the login to add, null when it asked for a login (S-59)
     */
    public function __construct(
        public string $route,
        public array $parameters,
        public ?StepUpOffer $stepUp = null,
    ) {
    }
}
