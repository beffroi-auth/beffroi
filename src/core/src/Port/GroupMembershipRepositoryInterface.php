<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Group\GroupMembership;

interface GroupMembershipRepositoryInterface
{
    public function save(GroupMembership $membership): void;

    /**
     * @return bool false when the row was already gone, another write having removed it first
     */
    public function remove(GroupMembership $membership): bool;
}
