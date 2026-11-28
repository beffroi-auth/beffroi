<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    private Tenant $tenant;

    private Tenant $other;

    private User $alice;

    private InMemoryUserRepository $users;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->other = Fixtures::tenant('other', 'https://id.other.example');
        $this->alice = Fixtures::user($this->tenant, 'alice', 'alice-subject');
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
        $this->users->save(Fixtures::user($this->other, 'alice', 'alice-subject'));
        $this->users->save(Fixtures::user($this->other, 'bob', 'bob-subject'));
    }

    #[Test]
    public function aUserIsFoundById(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->find($this->alice->id));
    }

    #[Test]
    public function noUserIsFoundForAnUnknownId(): void
    {
        // When / Then
        static::assertNull($this->users->find(Uuid::v7()));
    }

    #[Test]
    public function aUserIsFoundBySubjectWithinItsTenant(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->findBySubject($this->tenant, new Subject('alice-subject')));
    }

    #[Test]
    public function aSubjectOfAnotherTenantIsNotFound(): void
    {
        // When / Then
        static::assertNull($this->users->findBySubject($this->tenant, new Subject('bob-subject')));
    }

    #[Test]
    public function aUserIsFoundByUsernameWithinItsTenant(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->findByUsername($this->tenant, 'alice'));
        static::assertNotSame($this->alice, $this->users->findByUsername($this->other, 'alice'));
    }

    /**
     * RFC 8265 §3.3.4: as the storage holds a username written before the profile applied.
     */
    #[Test]
    public function aUsernameAsWrittenFindsThePersonWrittenSoBeforeOneComparingAsIt(): void
    {
        // Given
        $written = Fixtures::user($this->tenant, 'Alice', 'other-alice-subject');
        $this->users->save($written);

        // When / Then
        static::assertSame($written, $this->users->findByUsername($this->tenant, 'Alice'));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function anotherSpellingOfAUsernameFindsThePersonWhoseUsernameComparesAsIt(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->findByUsername($this->tenant, 'ALICE'));
    }

    #[Test]
    public function aUsernameOfAnotherTenantIsNotFound(): void
    {
        // When / Then
        static::assertNull($this->users->findByUsername($this->tenant, 'bob'));
    }

    #[Test]
    public function aUserWithoutCredentialHasNone(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();

        // When / Then
        static::assertSame([], $repository->findByUser($this->alice, PasswordCredential::class));
    }

    #[Test]
    public function theCredentialsOfAKindAreFoundAmongThoseOfOtherUsersAndKinds(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $password = new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(new Argon2id(), '$argon2id$x'), Fixtures::now());
        $repository->save($password);
        $repository->save(Fixtures::passkey($this->alice));
        $repository->save(
            new PasswordCredential(
                Uuid::v7(),
                Fixtures::user(username: 'bob', subject: 'bob-subject'),
                new PasswordHash(new Argon2id(), '$argon2id$y'),
                Fixtures::now(),
            ),
        );

        // When / Then
        static::assertSame([$password], $repository->findByUser($this->alice, PasswordCredential::class));
    }

    #[Test]
    public function theCredentialsOfAUserAreListedOldestFirstWithoutThoseOfOtherUsers(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $passkey = Fixtures::passkey($this->alice, createdAt: Fixtures::now()->modify('-1 day'));
        $password = new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(new Argon2id(), '$argon2id$x'), Fixtures::now());
        $repository->save($password);
        $repository->save($passkey);
        $repository->save(
            new PasswordCredential(
                Uuid::v7(),
                Fixtures::user(username: 'bob', subject: 'bob-subject'),
                new PasswordHash(new Argon2id(), '$argon2id$y'),
                Fixtures::now(),
            ),
        );

        // When / Then
        static::assertSame([$passkey, $password], $repository->findByUser($this->alice));
    }

    #[Test]
    public function aCredentialIsFoundByItsIdentifierWhateverItsKind(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $passkey = Fixtures::passkey($this->alice);
        $repository->save($passkey);

        // When / Then
        static::assertSame($passkey, $repository->find($passkey->id));
        static::assertNull($repository->find(Uuid::v7()));
    }

    #[Test]
    public function aPasskeyIsFoundByItsCredentialIdWithinItsTenant(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $passkey = Fixtures::passkey($this->alice, credentialId: 'credential-of-alice');
        $repository->save($passkey);

        // When / Then
        static::assertSame($passkey, $repository->findByExternalId($this->tenant, PasskeyCredential::class, 'credential-of-alice'));
        static::assertNull($repository->findByExternalId($this->other, PasskeyCredential::class, 'credential-of-alice'));
    }

    #[Test]
    public function aPasswordIsNeverFoundByAnExternalIdentifier(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $repository->save(new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(new Argon2id(), '$argon2id$x'), Fixtures::now()));

        // When / Then
        static::assertNull($repository->findByExternalId($this->tenant, PasswordCredential::class, '$argon2id$x'));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aTenantHoldsAPasswordHashedAsTypedWhileOneOfItsPersonsDoes(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $repository->save(Fixtures::hashedAsTyped(Fixtures::password($this->alice)));

        // When / Then
        static::assertTrue($repository->remainIn($this->tenant));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aTenantWhosePasswordsWereAllPosedUnderTheProfileHoldsNoneHashedAsTyped(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $repository->save(Fixtures::password($this->alice));

        // When / Then
        static::assertFalse($repository->remainIn($this->tenant));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function thePasswordsHashedAsTypedOfATenantAreCountedWithoutThoseOfAnother(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $repository->save(Fixtures::hashedAsTyped(Fixtures::password($this->alice)));
        $repository->save(Fixtures::password(Fixtures::user($this->tenant, 'carol', 'carol-subject')));
        $repository->save(Fixtures::hashedAsTyped(Fixtures::password(Fixtures::user($this->other, 'bob', 'bob-subject'))));

        // When / Then
        static::assertSame(1, $repository->countIn($this->tenant));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aPasswordHashedAsTypedInAnotherTenantIsNotOneOfThisTenant(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $repository->save(Fixtures::hashedAsTyped(Fixtures::password(Fixtures::user($this->other, 'bob', 'bob-subject'))));

        // When / Then
        static::assertFalse($repository->remainIn($this->tenant));
    }
}
