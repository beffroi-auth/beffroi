<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctor;

use App\Doctor\PasswordsHashedAsTypedLeft;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Doctrine\DBAL\Types\Types;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

final class PasswordsHashedAsTypedLeftTest extends DatabaseTestCase
{
    /**
     * Decision 0065
     */
    #[Test]
    public function aTenantThatHoldsNoHashOfBeforeSaysThatASignInVerifiesOneForm(): void
    {
        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [true, [sprintf('No password of the tenant "%s" is hashed as typed: a sign-in verifies one form.', self::tenant()->slug)]],
            [$finding->green, $finding->lines],
        );
    }

    /**
     * Decision 0065
     */
    #[Test]
    public function aTenantThatHoldsHashesOfBeforeCountsThem(): void
    {
        // Given
        $credential = new PasswordCredential(Uuid::v7(), self::user(), new PasswordHash(new Argon2id(), '$argon2id$hash'), self::now());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);
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

        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [
                true,
                [sprintf(
                    '1 password(s) of the tenant "%s" are hashed as typed, before the profile: every sign-in of the tenant verifies two forms until the last is replaced at the sign-in of its person.',
                    self::tenant()->slug,
                )],
            ],
            [$finding->green, $finding->lines],
        );
    }

    private static function check(): PasswordsHashedAsTypedLeft
    {
        return self::service(PasswordsHashedAsTypedLeft::class, PasswordsHashedAsTypedLeft::class);
    }
}
