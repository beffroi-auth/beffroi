<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Authentication;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\CanFindUnendedSessionsInterface;
use Closure;
use Symfony\Component\Uid\Uuid;

/**
 * Ends the sessions of a person, every one or every one but the session kept, each through SessionTerminator, never in
 * bulk, so that each leaves its trace and its back-channel logout. Expired sessions are ended too: expiry ends nothing,
 * and their refresh tokens would live on.
 */
final readonly class OtherSessionsTermination
{
    public function __construct(
        private CanFindUnendedSessionsInterface $sessions,
        private SessionTerminator $terminator,
    ) {
    }

    /**
     * The person ends them from the session they keep.
     */
    public function endEveryOther(AuthenticationSession $kept, RequestContext $context): int
    {
        return $this->endEach($kept->user, $kept->id, function (AuthenticationSession $session) use ($context): void {
            $this->terminator->end($session, SessionEnd::User, new ThePerson(), $context);
        });
    }

    /**
     * The act of each end names its author (decision 0066).
     */
    public function endEvery(User $user, SessionEnd $by, AuthorInterface $author, RequestContext $context): int
    {
        return $this->endEach($user, null, function (AuthenticationSession $session) use ($by, $author, $context): void {
            $this->terminator->end($session, $by, $author, $context);
        });
    }

    /**
     * @param Closure(AuthenticationSession): void $end
     */
    private function endEach(User $user, ?Uuid $kept, Closure $end): int
    {
        $ended = 0;
        foreach ($this->sessions->findUnendedByUser($user) as $session) {
            if ($kept !== null && $session->id->equals($kept)) {
                continue;
            }
            $end($session);
            ++$ended;
        }

        return $ended;
    }
}
