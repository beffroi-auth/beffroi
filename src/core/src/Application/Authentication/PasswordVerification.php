<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Authentication;

use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\TypedPassword;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasswordRehashed;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordAttemptLimiterInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use function trim;

/**
 * The attempt is counted as soon as the user is named, before anything is verified, and once whatever the number of
 * forms of the password verified (decision 0014). What is verified is the form OpaqueString enforces, then the bytes as
 * typed when they differ (RFC 8265 §4.2.3, §8.2).
 */
final readonly class PasswordVerification
{
    public function __construct(
        private UserRepositoryInterface $users,
        private CredentialRepositoryInterface $credentials,
        private ActivePassword $activePassword,
        private PasswordHasherInterface $hasher,
        private DecoyHash $decoy,
        private PasswordAttemptLimiterInterface $attempts,
        private AuthenticationRefusal $refusals,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private FederatedDomains $federated,
    ) {
    }

    /**
     * @throws AuthenticationFailedException
     */
    public function verify(
        Tenant $tenant,
        string $identifier,
        #[SensitiveParameter]
        string $password,
        RequestContext $context,
    ): PasswordCredential {
        // No decoy hash here: this refusal says nothing of the account, and an Argon2id per request would be a
        // cost anybody could ask this provider to pay.
        if (! $tenant->loginFloor->admits([PasswordCredential::method()])) {
            throw $this->refusals->refuse(
                $tenant,
                $context,
                AuthenticationFailureReason::BelowTheFloor,
                AuthenticationMethod::password(),
                $identifier,
                null,
            );
        }

        $typed = TypedPassword::of($password);
        $user = $this->users->findByUsername($tenant, trim($identifier));
        if ($user === null) {
            throw $this->refuseAtTheCostOfAPassword($tenant, $context, AuthenticationFailureReason::UnknownUser, $identifier, $password, $typed, null);
        }

        if (! $this->attempts->attempt($user)) {
            throw $this->refuseAtTheCostOfAPassword($tenant, $context, AuthenticationFailureReason::TooManyAttempts, $identifier, $password, $typed, $user);
        }

        $credential = $this->activePassword->of($user);
        if ($credential === null) {
            throw $this->refuseAtTheCostOfAPassword($tenant, $context, AuthenticationFailureReason::NoSuchCredential, $identifier, $password, $typed, $user);
        }

        if ($typed === null) {
            throw $this->refuseAtTheCostOfAPassword($tenant, $context, AuthenticationFailureReason::InvalidCredential, $identifier, $password, null, $user);
        }

        $hash = $credential->hash;
        $replaced = $this->hasher->needsRehash($hash);
        $verified = $typed->verifiedBy(fn (#[SensitiveParameter] string $form): bool => $replaced
            ? $this->decoy->verifyNoFaster($hash, $form)
            : $this->hasher->verify($hash, $form));
        if ($verified === null) {
            throw $this->refusals->refuse(
                $tenant,
                $context,
                AuthenticationFailureReason::InvalidCredential,
                AuthenticationMethod::password(),
                $identifier,
                $user,
            );
        }

        // After the password on purpose: a disabled account answers like a wrong password.
        if (! $user->isEnabled()) {
            throw $this->refusals->refuse($tenant, $context, AuthenticationFailureReason::DisabledUser, AuthenticationMethod::password(), $identifier, $user);
        }

        // Also after the password: the page offers a federated person no password, but a forged post gets here.
        if (! $this->federated->admitsLocalCredentials($user)) {
            throw $this->refusals->refuse(
                $tenant,
                $context,
                AuthenticationFailureReason::FederatedDomain,
                AuthenticationMethod::password(),
                $identifier,
                $user,
            );
        }

        $this->attempts->reset($user);
        $now = $this->clock->now();
        $credential->recordUse($now);
        // The bytes as typed verify only a hash computed over them before the profile was enforced.
        if ($replaced || $verified !== $typed->enforced) {
            $credential->rehash($this->hasher->hash($typed->enforced), $now);
            $this->credentials->save($credential);
            $this->events->dispatch(new PasswordRehashed($credential, $now, $context));
        } else {
            $this->credentials->save($credential);
        }
        $this->events->dispatch(new PasswordUsed($credential, $now, $context));

        return $credential;
    }

    /**
     * The decoy is verified once for each form a password of the account would be verified under, once when the
     * profile refuses what was typed.
     */
    private function refuseAtTheCostOfAPassword(
        Tenant $tenant,
        RequestContext $context,
        AuthenticationFailureReason $reason,
        string $identifier,
        #[SensitiveParameter]
        string $password,
        ?TypedPassword $typed,
        ?User $user,
    ): AuthenticationFailedException {
        foreach ($typed?->forms() ?? [$password] as $form) {
            $this->decoy->verify($form);
        }

        return $this->refusals->refuse($tenant, $context, $reason, AuthenticationMethod::password(), $identifier, $user);
    }
}
