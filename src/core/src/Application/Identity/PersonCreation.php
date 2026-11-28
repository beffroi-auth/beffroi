<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Identity;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Event\PersonCreated;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A person the host, an administrator of the tenant or a directory creates, the creation an act of their account that
 * names its author (decisions 0022 and 0066). An upstream provider creates its people through `JustInTimeProvisioning`,
 * whose act is `person.provisioned`.
 */
final readonly class PersonCreation
{
    public function __construct(
        private UserProvisioner $provisioner,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param Subject|null $subject the subject an import brings, drawn when none is given
     *
     * @throws UserAlreadyExistsException
     * @throws InvalidArgumentException   when the username is empty or longer than 255 characters
     */
    public function create(
        Tenant $tenant,
        string $username,
        AuthorInterface $author,
        RequestContext $context,
        ?EmailAddress $email = null,
        bool $emailVerified = false,
        ?Subject $subject = null,
    ): User {
        $user = $this->provisioner->create($tenant, $username, $email, $emailVerified, $subject);
        $this->events->dispatch(new PersonCreated($tenant, $user->subject, $user->createdAt, $context, $author));

        return $user;
    }
}
