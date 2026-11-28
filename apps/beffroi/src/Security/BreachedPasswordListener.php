<?php

declare(strict_types=1);

namespace App\Security;

use App\Message\CheckThePasswordAgainstTheBreaches;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Domain\Credential\TypedPassword;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Runs on LoginSuccessEvent alone, so that nothing of a wrong guess is sent to anybody; the password is still on
 * the badge there, the firewall verifying no hash of its own. What is looked up is the form OpaqueString enforces,
 * the one that is hashed (RFC 8265 §8.2).
 */
final readonly class BreachedPasswordListener
{
    public function __construct(
        private BreachedPasswordsInterface $breaches,
        private MessageBusInterface $commandBus,
        private ClockInterface $clock,
    ) {
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $passport = $event->getPassport();
        $badge = $passport->getBadge(VerifiedPassword::class);
        $user = $event->getUser();
        if (! $badge instanceof VerifiedPassword || ! $user instanceof SecurityUser || ! $this->breaches->looksUp()) {
            return;
        }
        $credential = $user->passwordCredential();
        if ($credential === null || ! $credential->dueForABreachLookup($this->clock->now())) {
            return;
        }
        $password = TypedPassword::of($badge->password);
        if ($password === null) {
            return;
        }
        $this->commandBus->dispatch(new CheckThePasswordAgainstTheBreaches($credential->id, PasswordDigest::of($password->enforced)->value));
    }
}
