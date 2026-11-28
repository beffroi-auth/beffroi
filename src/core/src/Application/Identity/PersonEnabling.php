<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Identity;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Event\PersonEnabled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\UserRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A person who may sign in again. Nothing they held is given back, every session of theirs having ended with the
 * disabling. A person enabled already is left as they are, and nothing is announced.
 */
final readonly class PersonEnabling
{
    public function __construct(
        private UserRepositoryInterface $users,
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    /**
     * The act names the author (decision 0066).
     *
     * @return bool whether the person was disabled until now
     */
    public function enable(User $user, AuthorInterface $author, RequestContext $context): bool
    {
        if ($user->isEnabled()) {
            return false;
        }
        $now = $this->clock->now();
        $user->enable($now);
        $this->users->save($user);
        $this->events->dispatch(new PersonEnabled($user->tenant, $user->subject, $now, $context, $author));

        return true;
    }
}
