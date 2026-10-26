<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_any;
use Beffroi\Bundle\Http\StepUpOffer;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Authorization\AuthenticationRequirement;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Exception\OAuth2Exception;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * What a login at an upstream identity provider is asked, read from the rule the login page reads,
 * AuthenticationRequirement of beffroi/oidc, and never from a slice of it written again (beffroi/saml, spec/saml.md
 * S-49, S-58, S-59): whether the request the service provider sends forces a login, and what the client still asks once
 * the provider has answered.
 *
 * What the client asks is read against the session the login leaves the browser with, built here and never kept: the
 * session the browser holds when it is that person's, these proofs recorded on it, a new one otherwise, every proof
 * dated by the AuthnInstant and never later than now, as the session the login opens will date it (S-57). So a login
 * during the interaction satisfies prompt=login, a max_age and a step-up, an earlier one does not, and an id_token_hint
 * naming another person asks still, each as the login page would say it of that session.
 */
final readonly class UpstreamLoginRequirement
{
    public function __construct(
        private AuthenticationRequirement $requirement,
    ) {
    }

    /**
     * S-49: whether the request forces a login, one rule for an interaction and for a page. A browser that holds a
     * session forces one when the login is asked of it anyway: a page waits for it, which asks a person signed in for a
     * fresh proof or for one more, or the interaction asks more of that session than it holds, prompt=login, a max_age
     * it exceeds, a step-up, an id_token_hint naming another person, prompt=select_account. A browser that holds none
     * forces one for prompt=login alone.
     *
     * @param Interaction|null $interaction the interaction the login serves, null for the login a page waits for
     *
     * @throws OAuth2Exception when the authorization request is one the login page answers with an error, a hint whose
     *                         signature is not ours or an essential class nobody can prove
     */
    public function forcesALogin(?Interaction $interaction, ?AuthenticationSession $session, DateTimeImmutable $now): bool
    {
        if (! $session instanceof AuthenticationSession) {
            return $interaction?->request->hasPrompt(Prompt::Login) ?? false;
        }
        if (! $interaction instanceof Interaction) {
            return true;
        }

        return $this->requirement->of($this->requirement->beforeAnyLogin($interaction->request), $interaction, $session, $now) !== null;
    }

    /**
     * S-58: what the authorization request of the interaction still asks once that person signed in at the provider
     * with these methods at that instant, null when it asks nothing more.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     * @param AuthenticationSession|null $held the session the browser holds
     *
     * @throws OAuth2Exception when the authorization request is one the login page answers with an error
     */
    public function stillAsked(
        Interaction $interaction,
        User $person,
        array $methods,
        DateTimeImmutable $authenticatedAt,
        ?AuthenticationSession $held,
        RequestContext $context,
        DateTimeImmutable $now,
    ): ?LoginRequirement {
        $session = self::leftWith($person, $methods, $authenticatedAt, $held, $context, $now);

        return $this->requirement->of($this->requirement->beforeAnyLogin($interaction->request), $interaction, $session, $now)?->requirement;
    }

    /**
     * S-59: whether the login proves one of the classes of the step-up a page asked for, as the session it leaves the
     * browser with satisfies it under the policy of the tenant.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public function meets(
        StepUpOffer $stepUp,
        User $person,
        array $methods,
        DateTimeImmutable $authenticatedAt,
        ?AuthenticationSession $held,
        RequestContext $context,
        DateTimeImmutable $now,
    ): bool {
        $session = self::leftWith($person, $methods, $authenticatedAt, $held, $context, $now);
        $policy = $person->tenant->authenticationContextPolicy;

        return array_any($stepUp->classes, static function (string $name) use ($policy, $session): bool {
            $class = $policy->named($name);

            return $class !== null && $session->satisfies($class);
        });
    }

    /**
     * The session the login would leave the browser with, never kept.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    private static function leftWith(
        User $person,
        array $methods,
        DateTimeImmutable $authenticatedAt,
        ?AuthenticationSession $held,
        RequestContext $context,
        DateTimeImmutable $now,
    ): AuthenticationSession {
        $provenAt = $authenticatedAt > $now ? $now : $authenticatedAt;
        if ($held instanceof AuthenticationSession && $held->user->id->equals($person->id)) {
            $proofs = $held->proofs;
            foreach ($methods as $method) {
                $proofs = $proofs->with($method, $provenAt);
            }
        } else {
            $proofs = AuthenticationProofs::ofAll($methods, $provenAt);
        }

        return new AuthenticationSession(Uuid::v7(), $person->tenant, $person, $now, $proofs, $context, $now->modify('+1 second'));
    }
}
