<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Credential;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * NIST SP 800-63B-4 §4.1.2.1, §4.5, §4.6, NIST SP 800-63A-4 §5.3
 *
 * Carries no identifier of what changed and no link: the person reads the change on their account, signed in.
 */
final readonly class CredentialChange
{
    public Tenant $tenant;

    public Uuid $userId;

    public Subject $subject;

    /**
     * @param string               $act      the name of the act it tells
     * @param string|null          $kind     the kind of the credential it changed, or the claim of the channel, null when it changed none of them
     * @param ReplacedChannel|null $replaced the channel it took from the person while it was verified, which it is told to as well, and never in its text
     */
    public function __construct(
        User $user,
        public string $act,
        public DateTimeImmutable $occurredAt,
        public ?string $kind = null,
        public ?ReplacedChannel $replaced = null,
    ) {
        $this->tenant = $user->tenant;
        $this->userId = $user->id;
        $this->subject = $user->subject;
    }
}
