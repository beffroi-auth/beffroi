<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\UsernameUniquenessPendingException;
use Symfony\Component\Uid\Uuid;

interface UserRepositoryInterface
{
    public function find(Uuid $id): ?User;

    public function findBySubject(Tenant $tenant, Subject $subject): ?User;

    /**
     * RFC 8265 §3.3.4: the person whose username is the one given as written, and else the person whose username has
     * the same enforced form, so that a username written before the profile applied is found as it was written. A
     * username the profile refuses compares as written (`UsernameCaseMapped::comparisonForm()`).
     */
    public function findByUsername(Tenant $tenant, string $username): ?User;

    /**
     * Compared without regard to case, in no order a caller may rely on.
     *
     * @return list<User>
     */
    public function findAllByEmail(Tenant $tenant, EmailAddress $email): array;

    /**
     * @throws UsernameUniquenessPendingException when the person is new or renamed and the usernames of the tenant are
     *                                             not all compared by their enforced form yet
     */
    public function save(User $user): void;
}
