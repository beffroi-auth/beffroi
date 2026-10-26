<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Saml\Domain\Upstream\AuthnContextMethods;
use DateTimeImmutable;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The login of the firewall an upstream identity provider proves (beffroi/saml S-52, S-57): what its assertion proved,
 * read from the badge the assertion consumer service put on the passport, dated by its AuthnInstant and bounded by its
 * SessionNotOnOrAfter; every method it may prove, "fed" and the methods its classes of authentication map to exactly,
 * is what the provider announces of it. Its refusals are announced as those of every login of the firewall (S-53).
 * Tagged "beffroi.login" and "beffroi.login.refusal" only when the service provider of the tenant is enabled, so that a
 * deployment that receives no assertion announces nothing of one.
 */
final readonly class UpstreamLogin implements AnnouncesItsRefusalInterface, BoundsItsSessionInterface, DatesItsProofsInterface
{
    public function proofs(Passport $passport): ?array
    {
        return self::badge($passport)?->methods;
    }

    public function everyProvableMethod(): array
    {
        return AuthnContextMethods::everyProvable();
    }

    public function provenAt(Passport $passport): ?DateTimeImmutable
    {
        return self::badge($passport)?->provenAt;
    }

    public function sessionNotOnOrAfter(Passport $passport): ?DateTimeImmutable
    {
        return self::badge($passport)?->sessionNotOnOrAfter;
    }

    public function route(): string
    {
        return ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE;
    }

    /**
     * What the assertion consumer service refused, as it decided to announce it: a response it did not take, a person
     * it may not sign in, a login under the floor of the tenant, never a request sent once more nor the answer of a
     * client; or the account the checker refused after the response was taken. Nothing was typed, so the identifier is
     * null.
     */
    public function refusal(AuthenticationException $exception, ?Passport $passport): ?LoginFailure
    {
        if ($exception instanceof UpstreamLoginRefusedException) {
            return $exception->failure;
        }
        $reason = AuthenticationFailureCause::of($exception);
        if ($passport === null || $reason === null) {
            return null;
        }
        $badge = self::badge($passport);
        $user = $passport->getUser();
        if ($badge === null || ! $user instanceof SecurityUser) {
            return null;
        }

        return new LoginFailure($badge->methods[0], $reason, null, $user->user());
    }

    private static function badge(Passport $passport): ?UpstreamCredentials
    {
        $badge = $passport->getBadge(UpstreamCredentials::class);

        return $badge instanceof UpstreamCredentials ? $badge : null;
    }
}
