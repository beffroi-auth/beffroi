<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use function array_filter;
use function array_values;
use function is_array;
use App\Doctrine\EntityManagers;
use App\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Port\CanRevokeARefreshTokenOnceInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRotationInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use SortDirection;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * @extends DoctrineRepository<RefreshToken>
 */
final readonly class DoctrineRefreshTokenRepository extends DoctrineRepository implements
    CanRevokeARefreshTokenOnceInterface,
    DeadRecordsInterface,
    RefreshTokenRepositoryInterface,
    RefreshTokenRotationInterface,
    RefreshTokensOfAConsentInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
    ) {
        parent::__construct($managers, RefreshToken::class);
    }

    /**
     * A rotated token is kept until its family expires, so that its reuse is still detected (RFC 9700 §4.14.2).
     */
    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $familyOfToken = $this->sweep->joinColumn(RefreshToken::class, 'family');
        $familyKey = $this->sweep->column(RefreshTokenFamily::class, 'id');
        $familyExpiry = $this->sweep->column(RefreshTokenFamily::class, 'expiresAt');
        $families = $this->sweep->table(RefreshTokenFamily::class);

        $forgotten = $this->sweep->from(
            RefreshToken::class,
            $tenant,
            sprintf(
                '%s IN (SELECT %s FROM %s WHERE %s <= :now)',
                $familyOfToken,
                $familyKey,
                $families,
                $familyExpiry,
            ),
            $this->sweep->column(RefreshToken::class, 'issuedAt'),
            [
                'now' => $now,
            ],
            [
                'now' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );

        return $forgotten
        + $this->sweep->from(
            RefreshTokenFamily::class,
            $tenant,
            sprintf(
                '%s <= :now AND NOT EXISTS (SELECT 1 FROM %s WHERE %s = %s.%s)',
                $familyExpiry,
                $this->sweep->table(RefreshToken::class),
                $familyOfToken,
                $families,
                $familyKey,
            ),
            $familyExpiry,
            [
                'now' => $now,
            ],
            [
                'now' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
    }

    public function findByTokenHash(string $tokenHash): ?RefreshToken
    {
        $token = $this->repository()->findOneBy([
            'tokenHash' => $tokenHash,
        ]);

        return $token !== null && ClientResolver::isResolved($token) ? $token : null;
    }

    public function findByFamily(Uuid $family): array
    {
        return $this->resolved([
            'family' => $family,
        ]);
    }

    public function findByAuthorizationCode(string $codeHash): array
    {
        $tokens = $this->queryBuilder('token')
            ->join('token.family', 'family')
            ->where('family.grantingRecordHash = :hash')
            ->setParameter('hash', $codeHash)
            ->orderBy('token.issuedAt', SortDirection::Ascending)
            ->addOrderBy('token.tokenHash', SortDirection::Ascending)
            ->getQuery()
            ->getResult();

        return $this->onlyResolved(is_array($tokens) ? $tokens : []);
    }

    public function findBySession(Uuid $session): array
    {
        return $this->resolved([
            'session' => $session,
        ]);
    }

    /**
     * @return list<RefreshToken>
     */
    public function ofConsent(Consent $consent): array
    {
        /** @var list<RefreshToken> $tokens */
        $tokens = $this->queryBuilder('t')
            ->join('t.session', 's')
            ->where('s.user = :user')
            ->andWhere('t.clientId = :clientId')
            ->orderBy('t.issuedAt', SortDirection::Ascending)
            ->addOrderBy('t.tokenHash', SortDirection::Ascending)
            ->setParameter('user', $consent->user->id, UuidType::NAME)
            ->setParameter('clientId', $consent->clientId)
            ->getQuery()
            ->getResult();

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
    }

    /**
     * Through the connection, not the unit of work: of two requests presenting the same token, one rotates it.
     */
    public function rotate(RefreshToken $token, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(RefreshToken::class);
        $rotatedAt = $metadata->getColumnName('rotatedAt');
        $claimed =
            $manager->getConnection()->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = :now WHERE %s = :tokenHash AND %s IS NULL AND %s IS NULL',
                    $metadata->getTableName(),
                    $rotatedAt,
                    $metadata->getColumnName('tokenHash'),
                    $rotatedAt,
                    $metadata->getColumnName('revokedAt'),
                ),
                [
                    'now' => $now,
                    'tokenHash' => $token->tokenHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'tokenHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($claimed) {
            $token->rotate($now);
        }

        return $claimed;
    }

    /**
     * Through the connection, not the unit of work: of two workers revoking the same token, one revokes it, and the other
     * reads the moment it was revoked, a refresh of the entity refusing its read-only value objects.
     */
    public function revokeOnce(RefreshToken $token, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $connection = $manager->getConnection();
        $metadata = $manager->getClassMetadata(RefreshToken::class);
        $revokedAt = $metadata->getColumnName('revokedAt');
        $tokenHash = $metadata->getColumnName('tokenHash');
        $revoked =
            $connection->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = :now WHERE %s = :tokenHash AND %s IS NULL',
                    $metadata->getTableName(),
                    $revokedAt,
                    $tokenHash,
                    $revokedAt,
                ),
                [
                    'now' => $now,
                    'tokenHash' => $token->tokenHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'tokenHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($revoked) {
            $token->revoke($now);

            return true;
        }
        $first = $connection->convertToPHPValue(
            $connection->fetchOne(sprintf('SELECT %s FROM %s WHERE %s = :tokenHash', $revokedAt, $metadata->getTableName(), $tokenHash), [
                'tokenHash' => $token->tokenHash,
            ]),
            Types::DATETIME_IMMUTABLE,
        );
        if ($first instanceof DateTimeImmutable) {
            $token->revoke($first);
        }

        return false;
    }

    public function save(RefreshToken $token): void
    {
        $this->store($token);
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return list<RefreshToken>
     */
    private function resolved(array $criteria): array
    {
        return $this->onlyResolved($this->repository()->findBy($criteria, [
            'issuedAt' => 'ASC',
            'tokenHash' => 'ASC',
        ]));
    }

    /**
     * @param array<array-key, mixed> $tokens
     *
     * @return list<RefreshToken>
     */
    private function onlyResolved(array $tokens): array
    {
        return array_values(array_filter(
            $tokens,
            static fn (mixed $token): bool => $token instanceof RefreshToken && ClientResolver::isResolved($token),
        ));
    }
}
