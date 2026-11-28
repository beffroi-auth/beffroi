<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use DateTimeImmutable;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\DBAL\Types\Types;
use App\Doctrine\Type\BytesType;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordsHashedAsTypedInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Totps;
use function is_string;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use function random_bytes;
use function strtoupper;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.4, §5.3, Decision 0002
 */
final class DoctrineCredentialRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aPasswordCredentialComesBackWithItsTypedHash(): void
    {
        // Given
        $user = self::user();
        $hash = new PasswordHash(new Pbkdf2Sha256(), 'base64digest', [
            'salt' => 'c2FsdA',
            'iterations' => 27500,
        ]);
        $credential = new PasswordCredential(Uuid::v7(), $user, $hash, self::now());
        $credential->markUsed(self::now()->modify('+1 minute'));
        self::credentials()->save($credential);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasswordCredential::class)[0] ?? static::fail('The credential was not stored.');

        // Then
        static::assertTrue($found->id->equals($credential->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame(Pbkdf2Sha256::NAME, $found->hash->algorithm->name());
        static::assertSame('base64digest', $found->hash->encoded);
        static::assertSame(
            [
                'salt' => 'c2FsdA',
                'iterations' => 27500,
            ],
            $found->hash->parameters,
        );
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now(), $found->hashChangedAt);
        static::assertEquals(self::now()->modify('+1 minute'), $found->lastUsedAt);
    }

    #[Test]
    public function theCredentialsOfAUserOfEveryKindAreListedOldestFirst(): void
    {
        // Given
        $user = self::user();
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Argon2id(), '$argon2id$alice'), self::now());
        $passkey = self::passkey($user, createdAt: self::now()->modify('-1 day'));
        self::credentials()->save($password);
        self::credentials()->save($passkey);
        self::reload();

        // When
        $listed = self::credentials()->findByUser($user);

        // Then
        static::assertCount(2, $listed);
        static::assertTrue($listed[0]->id->equals($passkey->id));
        static::assertTrue($listed[1]->id->equals($password->id));
    }

    #[Test]
    public function aPasskeyComesBackWithItsRecordItsNameAndItsDates(): void
    {
        // Given
        $user = self::user();
        $handle = Fixtures::userHandle();
        $credentialId = random_bytes(32);
        $aaguid = Uuid::v4();
        $passkey = new PasskeyCredential(
            Uuid::v7(),
            $user,
            'Pixel',
            $credentialId,
            "\xa5\x01\x02\x03\x26",
            7,
            ['internal', 'hybrid'],
            true,
            true,
            $aaguid,
            $handle,
            self::now(),
        );
        $passkey->markUsed(self::now()->modify('+1 minute'));
        $passkey->revoke(self::now()->modify('+2 minutes'));
        self::credentials()->save($passkey);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasskeyCredential::class)[0] ?? static::fail('The passkey was not stored.');

        // Then
        static::assertTrue($found->id->equals($passkey->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('Pixel', $found->name);
        static::assertSame($credentialId, $found->credentialId);
        static::assertSame("\xa5\x01\x02\x03\x26", $found->publicKey);
        static::assertSame(7, $found->signCount);
        static::assertSame(['internal', 'hybrid'], $found->transports);
        static::assertTrue($found->backupEligible);
        static::assertTrue($found->backedUp);
        static::assertTrue($found->aaguid->equals($aaguid));
        static::assertTrue($found->userHandle->equals($handle));
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now()->modify('+1 minute'), $found->lastUsedAt);
        static::assertEquals(self::now()->modify('+2 minutes'), $found->revokedAt);
    }

    #[Test]
    public function aUseIsWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $passkey = self::passkey($user, synced: true);
        self::credentials()->save($passkey);
        $passkey->recordUse(Fixtures::authenticatorData(backupEligible: true, backedUp: true, signCount: 12), self::now()->modify('+1 hour'));
        self::credentials()->save($passkey);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasskeyCredential::class)[0] ?? static::fail('The passkey was not stored.');

        // Then
        static::assertSame(12, $found->signCount);
        static::assertTrue($found->backupEligible);
        static::assertTrue($found->backedUp);
        static::assertEquals(self::now()->modify('+1 hour'), $found->lastUsedAt);
    }

    #[Test]
    public function aCredentialIsFoundByItsIdentifierWhateverItsKind(): void
    {
        // Given
        $user = self::user();
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Argon2id(), '$argon2id$alice'), self::now());
        $passkey = self::passkey($user);
        self::credentials()->save($password);
        self::credentials()->save($passkey);
        self::reload();

        // When / Then
        static::assertInstanceOf(PasswordCredential::class, self::credentials()->find($password->id));
        static::assertInstanceOf(PasskeyCredential::class, self::credentials()->find($passkey->id));
        static::assertNull(self::credentials()->find(Uuid::v7()));
    }

    #[Test]
    public function aPasskeyIsFoundByItsCredentialIdWithinTheTenant(): void
    {
        // Given
        $user = self::user();
        $credentialId = random_bytes(16);
        $passkey = self::passkey($user, $credentialId);
        self::credentials()->save($passkey);
        self::reload();

        // When
        $found = self::credentials()->findByExternalId(self::tenant(), PasskeyCredential::class, $credentialId);

        // Then
        static::assertNotNull($found);
        static::assertTrue($found->id->equals($passkey->id));
        static::assertNull(self::credentials()->findByExternalId(self::tenant(), PasskeyCredential::class, random_bytes(16)));
    }

    #[Test]
    public function aPasswordHasNoExternalIdentifier(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        self::credentials()->findByExternalId(self::tenant(), PasswordCredential::class, '$argon2id$alice');
    }

    /**
     * WebAuthn Level 3 §7.1, step 26
     */
    #[Test]
    public function aSecondPasskeyWithTheSameCredentialIdIsRefusedByTheTable(): void
    {
        // Given
        $credentialId = random_bytes(16);
        self::credentials()->save(self::passkey(self::user(), $credentialId));

        // Then
        $this->expectException(UniqueConstraintViolationException::class);

        // When
        self::credentials()->save(self::passkey(self::user('bob', 'bob-subject'), $credentialId));
    }

    #[Test]
    public function aRehashIsWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Bcrypt(), '$2y$old'), self::now());
        self::credentials()->save($credential);
        $credential->rehash(new PasswordHash(new Argon2id(), '$argon2id$new'), self::now()->modify('+1 hour'));
        self::credentials()->save($credential);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, PasswordCredential::class)[0] ?? static::fail('The credential was not stored.');

        // Then
        static::assertSame(Argon2id::NAME, $found->hash->algorithm->name());
        static::assertSame('$argon2id$new', $found->hash->encoded);
        static::assertSame([], $found->hash->parameters);
        static::assertEquals(self::now()->modify('+1 hour'), $found->hashChangedAt);
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aRowWrittenBeforeTheProfileKeepsItsTenantHoldingAPasswordHashedAsTyped(): void
    {
        // Given
        self::writtenBeforeTheProfile(self::passwordOf(self::user()));

        // When / Then
        static::assertTrue(self::hashedAsTyped()->remainIn(self::tenant()));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aPasswordWrittenUnderTheProfileIsNoneHashedAsTyped(): void
    {
        // Given
        self::passwordOf(self::user());

        // When / Then
        static::assertFalse(self::hashedAsTyped()->remainIn(self::tenant()));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function theRehashOfTheLastRowWrittenBeforeTheProfileLeavesNone(): void
    {
        // Given
        $user = self::user();
        self::writtenBeforeTheProfile(self::passwordOf($user));
        self::reload();
        $credential = self::credentials()->findByUser($user, PasswordCredential::class)[0] ?? static::fail('The credential was not stored.');
        $credential->rehash(new PasswordHash(new Argon2id(), '$argon2id$enforced'), self::now()->modify('+1 hour'));
        self::credentials()->save($credential);

        // When / Then
        static::assertFalse(self::hashedAsTyped()->remainIn(self::tenant()));
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aRowOfAnotherTenantWrittenBeforeTheProfileIsNotOfThisTenant(): void
    {
        // Given
        $other = new Tenant(Uuid::v7(), 'other', new Issuer('https://other.test'), 'Other', self::now());
        self::entityManager()->persist($other);
        $bob = User::create(Uuid::v7(), $other, new Subject('bob-subject'), 'bob', self::now());
        self::entityManager()->persist($bob);
        self::writtenBeforeTheProfile(self::passwordOf($bob));

        // When / Then
        static::assertFalse(self::hashedAsTyped()->remainIn(self::tenant()));
    }

    #[Test]
    public function aUserWithoutPasswordHasNone(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        self::credentials()->save(new PasswordCredential(Uuid::v7(), self::user(), new PasswordHash(new Argon2id(), '$argon2id$alice'), self::now()));
        self::reload();

        // When / Then
        static::assertSame([], self::credentials()->findByUser($bob, PasswordCredential::class));
        static::assertSame([], self::credentials()->findByUser($bob));
    }

    #[Test]
    public function aTotpComesBackWithItsSealedSecretItsStepItsBackupCodesAndItsDates(): void
    {
        // Given
        $user = self::user();
        $totp = self::totp($user);
        $totp->recordUse(59_000_001, self::now()->modify('+1 minute'));
        $totp->spendBackupCode(3, self::now()->modify('+2 minutes'));
        $totp->revoke(self::now()->modify('+3 minutes'));
        self::credentials()->save($totp);
        self::reload();

        // When
        $found = self::credentials()->findByUser($user, TotpCredential::class)[0] ?? static::fail('The credential was not stored.');

        // Then
        static::assertTrue($found->id->equals($totp->id));
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame(Totps::SEED, self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)
            ->unseal(self::tenant(), $found->sealedSecret));
        static::assertSame(59_000_001, $found->lastAcceptedStep);
        static::assertCount(10, $found->backupCodes);
        static::assertTrue($found->backupCodes[3]->isSpent());
        static::assertEquals(self::now()->modify('+2 minutes'), $found->backupCodes[3]->usedAt);
        static::assertFalse($found->backupCodes[4]->isSpent());
        static::assertTrue(new FakePasswordHasher()->verify($found->backupCodes[4]->hash, 'B5CDEFGHJ6'));
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now()->modify('+2 minutes'), $found->lastUsedAt);
        static::assertEquals(self::now()->modify('+3 minutes'), $found->revokedAt);
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    public function theRowHoldsTheSecretAsAnEnvelopeAndNothingElse(): void
    {
        // Given
        $totp = self::totp(self::user());
        self::credentials()->save($totp);

        // When
        $row = self::entityManager()->getConnection()->fetchAssociative('SELECT * FROM beffroi_totp_credential WHERE id = ?', [$totp->id->toBinary()]);

        // Then
        static::assertIsArray($row);
        static::assertIsString($row['sealed_secret']);
        static::assertNotSame('', Envelope::fromBytes(BytesType::decode($row['sealed_secret']) ?? '')->ciphertext);
        foreach ($row as $column => $value) {
            if (! is_string($value)) {
                continue;
            }
            static::assertStringNotContainsString(Totps::SEED, $value, $column);
            static::assertStringNotContainsString(Base32::encodeUpperUnpadded(Totps::SEED), $value, $column);
            static::assertStringNotContainsString(Base32::encodeUpperUnpadded(Totps::SEED), strtoupper($value), $column);
        }
    }

    /**
     * RFC 6238
     */
    private static function totp(User $user): TotpCredential
    {
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), Totps::SEED);

        return new TotpCredential(Uuid::v7(), $user, $sealed, Totps::credential($user, new FakePasswordHasher())->backupCodes, 59_000_000, self::now());
    }

    /**
     * WebAuthn Level 3 §6.1.3
     */
    private static function passkey(User $user, ?string $credentialId = null, ?DateTimeImmutable $createdAt = null, bool $synced = false): PasskeyCredential
    {
        return new PasskeyCredential(
            Uuid::v7(),
            $user,
            'YubiKey 5',
            $credentialId ?? random_bytes(16),
            'cose-public-key',
            0,
            ['usb'],
            $synced,
            false,
            Uuid::v4(),
            Fixtures::userHandle(),
            $createdAt ?? self::now(),
        );
    }

    private static function passwordOf(User $user): PasswordCredential
    {
        $credential = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Argon2id(), '$argon2id$hash'), self::now());
        self::credentials()->save($credential);

        return $credential;
    }

    /**
     * What the default of the column gives a row a migration found, or one a process of the version before inserted.
     */
    private static function writtenBeforeTheProfile(PasswordCredential $credential): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE beffroi_password_credential SET hashed_as_typed = :hashed_as_typed WHERE id = :id',
                [
                    'hashed_as_typed' => true,
                    'id' => $credential->id,
                ],
                [
                    'hashed_as_typed' => Types::BOOLEAN,
                    'id' => UuidType::NAME,
                ],
            );
    }

    private static function hashedAsTyped(): PasswordsHashedAsTypedInterface
    {
        return self::service('test.beffroi.passwords_hashed_as_typed', PasswordsHashedAsTypedInterface::class);
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class);
    }
}
