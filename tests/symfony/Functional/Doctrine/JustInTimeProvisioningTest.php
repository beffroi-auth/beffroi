<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusalReason;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusedException;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use function array_map;

/**
 * Issue #781: a person an upstream provider creates is the person, its source and its linked identity, kept
 * all or none. A person kept without the identity that names it would be a person no sign-in finds, whose
 * address refuses every creation after it.
 */
final class JustInTimeProvisioningTest extends DatabaseTestCase
{
    private const string ADDRESS = 'alice@acme.example';

    /**
     * The store of linked identities finds through Doctrine and refuses every write, counting them: the
     * failure comes after the person was written, in the same transaction, and must take it back.
     */
    #[Test]
    public function aPersonWhoseLinkedIdentityFailsToBeWrittenIsNotKept(): void
    {
        // Given
        $identities = new class(self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)) implements
            LinkedIdentityRepositoryInterface {
            public private(set) int $refused = 0;

            public function __construct(
                private readonly LinkedIdentityRepositoryInterface $stored,
            ) {
            }

            public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
            {
                return $this->stored->find($tenant, $provider, $subject);
            }

            public function save(LinkedIdentity $identity): void
            {
                ++$this->refused;

                throw new RuntimeException('The linked identity could not be written.');
            }
        };
        $clock = new MockClock(self::now());
        $provisioning = new JustInTimeProvisioning(
            $identities,
            self::users(),
            self::service('test.beffroi.user_provisioner', UserProvisioner::class),
            new IdentityLinker($identities, new SymfonyUuidGenerator(), $clock),
            new RecordingEventDispatcher(),
            $clock,
            self::service('test.beffroi.atomic_writes', AtomicWritesInterface::class),
            new SymfonyUuidGenerator(),
            self::service('test.beffroi.upstream_memberships', UpstreamMemberships::class),
        );

        // When
        try {
            $provisioning->personNamedBy(
                self::tenant(),
                new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')], ['given_name']),
                'a7f3c2e1-alice',
                new EmailAddress(self::ADDRESS),
                [
                    'given_name' => 'Alice',
                ],
                self::context(),
            );
        } catch (RuntimeException) {
        }

        // Then
        static::assertSame(1, $identities->refused);
        static::assertSame([], self::users()->findAllByEmail(self::tenant(), new EmailAddress(self::ADDRESS)));
        static::assertSame([], self::entityManager()->getUnitOfWork()->getIdentityMap()[User::class] ?? []);
    }

    /**
     * beffroi/saml S-56: a first sign-in that loses a race at the table, alice written by another sign-in between the
     * checks and the unit, which the stores see here as not there yet, is answered by the refusal of the core and not
     * by the violation of the table, and leaves nothing managed by the entity manager.
     */
    #[Test]
    public function aFirstSignInThatLosesARaceAtTheTableIsRefusedAndLeavesNothingManaged(): void
    {
        // Given
        $alice = self::provisioning(self::linkedIdentities(), self::users())
            ->personNamedBy(
                self::tenant(),
                self::provider(),
                'a7f3c2e1-alice',
                new EmailAddress(self::ADDRESS),
                [],
                self::context(),
            );
        self::entityManager()->clear();
        $identities = new readonly class(self::linkedIdentities()) implements LinkedIdentityRepositoryInterface {
            public function __construct(
                private LinkedIdentityRepositoryInterface $stored,
            ) {
            }

            public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
            {
                return null;
            }

            public function save(LinkedIdentity $identity): void
            {
                $this->stored->save($identity);
            }
        };
        $users = new readonly class(self::users()) implements UserRepositoryInterface {
            public function __construct(
                private UserRepositoryInterface $stored,
            ) {
            }

            public function find(Uuid $id): ?User
            {
                return $this->stored->find($id);
            }

            public function findBySubject(Tenant $tenant, Subject $subject): ?User
            {
                return $this->stored->findBySubject($tenant, $subject);
            }

            public function findByUsername(Tenant $tenant, string $username): ?User
            {
                return null;
            }

            public function findAllByEmail(Tenant $tenant, EmailAddress $email): array
            {
                return [];
            }

            public function save(User $user): void
            {
                $this->stored->save($user);
            }
        };

        // When
        try {
            self::provisioning($identities, $users)
                ->personNamedBy(
                    self::tenant(),
                    self::provider(),
                    'a7f3c2e1-alice',
                    new EmailAddress(self::ADDRESS),
                    [],
                    self::context(),
                );
            static::fail('The sign-in was not refused.');
        } catch (UpstreamProvisioningRefusedException $refusal) {
            // Then
            static::assertSame(UpstreamProvisioningRefusalReason::IdentityLinkedMeanwhile, $refusal->reason);
            static::assertSame([], self::entityManager()->getUnitOfWork()->getIdentityMap()[User::class] ?? []);
            static::assertSame([$alice->id->toRfc4122()], array_map(
                static fn (User $user): string => $user->id->toRfc4122(),
                self::users()->findAllByEmail(self::tenant(), new EmailAddress(self::ADDRESS)),
            ));
        }
    }

    /**
     * beffroi/saml S-56: a sign-in that loses a race on a membership, another sign-in of the same person having given it
     * the group meanwhile, which the memberships read here do not see yet, is answered by the refusal of the core and
     * not by the violation of the table, and leaves nothing managed by the entity manager.
     */
    #[Test]
    public function aSignInThatLosesARaceOnAMembershipIsRefusedAndLeavesNothingManaged(): void
    {
        // Given
        $staff = new Group(Uuid::v7(), self::tenant(), 'Staff', GroupSource::Local, self::now());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($staff);
        $mapping = new GroupMapping(['staff' => $staff]);
        self::provisioning(self::linkedIdentities(), self::users())
            ->personNamedBy(
                self::tenant(),
                self::provider(),
                'a7f3c2e1-alice',
                new EmailAddress(self::ADDRESS),
                [],
                self::context(),
                null,
                $mapping,
                ['staff'],
            );
        self::entityManager()->clear();
        $notThereYet = new readonly class implements GroupsOfAPersonInterface {
            public function of(User $user): array
            {
                return [];
            }
        };
        $memberships = new UpstreamMemberships(
            $notThereYet,
            self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class),
            new SymfonyUuidGenerator(),
            new MockClock(self::now()),
        );

        // When
        try {
            self::provisioning(self::linkedIdentities(), self::users(), $memberships)
                ->personNamedBy(
                    self::tenant(),
                    self::provider(),
                    'a7f3c2e1-alice',
                    new EmailAddress(self::ADDRESS),
                    [],
                    self::context(),
                    null,
                    new GroupMapping([
                        'staff' => self::service('test.beffroi.groups', GroupRepositoryInterface::class)
                            ->findByName(self::tenant(), 'Staff') ?? static::fail('The group is gone.'),
                    ]),
                    ['staff'],
                );
            static::fail('The sign-in was not refused.');
        } catch (UpstreamProvisioningRefusedException $refusal) {
            // Then
            static::assertSame(
                [UpstreamProvisioningRefusalReason::MembershipWrittenMeanwhile, []],
                [$refusal->reason, self::entityManager()->getUnitOfWork()->getIdentityMap()[User::class] ?? []],
            );
        }
    }

    private static function provisioning(
        LinkedIdentityRepositoryInterface $identities,
        UserRepositoryInterface $users,
        ?UpstreamMemberships $memberships = null,
    ): JustInTimeProvisioning {
        $clock = new MockClock(self::now());

        return new JustInTimeProvisioning(
            $identities,
            $users,
            self::service('test.beffroi.user_provisioner', UserProvisioner::class),
            new IdentityLinker($identities, new SymfonyUuidGenerator(), $clock),
            new RecordingEventDispatcher(),
            $clock,
            self::service('test.beffroi.atomic_writes', AtomicWritesInterface::class),
            new SymfonyUuidGenerator(),
            $memberships ?? self::service('test.beffroi.upstream_memberships', UpstreamMemberships::class),
        );
    }

    private static function provider(): UpstreamProvider
    {
        return new UpstreamProvider('https://idp.acme.example/saml', [new EmailDomain('acme.example')]);
    }

    private static function linkedIdentities(): LinkedIdentityRepositoryInterface
    {
        return self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class);
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
