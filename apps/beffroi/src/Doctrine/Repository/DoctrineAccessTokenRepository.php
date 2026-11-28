<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use function array_filter;
use function array_merge;
use function array_values;
use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use App\Doctrine\EntityManagers;
use App\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokenInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use function is_subclass_of;
use function sort;
use function sprintf;
use function usort;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

final class DoctrineAccessTokenRepository implements
    AccessTokenRepositoryInterface,
    CanRevokeAccessTokenInterface,
    CanRevokeAccessTokensByConsentInterface,
    CanRevokeAccessTokensByGrantInterface,
    CanRevokeAccessTokensBySessionInterface,
    DeadRecordsInterface
{
    /**
     * @var list<class-string<StoredAccessToken>>|null
     */
    private ?array $kinds = null;

    public function __construct(
        private readonly EntityManagers $managers,
        private readonly BoundedDelete $sweep,
    ) {
    }

    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $forgotten = 0;
        foreach ($this->kinds() as $kind) {
            $expiry = $this->sweep->column($kind, 'expiresAt');
            $forgotten += $this->sweep->from(
                $kind,
                $tenant,
                sprintf('%s <= :now', $expiry),
                $expiry,
                [
                    'now' => $now,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                ],
                $limit,
            );
        }

        return $forgotten;
    }

    public function save(StoredAccessToken $token): void
    {
        $manager = $this->managers->forClass($token::class);
        $manager->persist($token);
        $manager->flush();
    }

    public function find(string $token): ?StoredAccessToken
    {
        $tokenHash = DrawnSecret::digestOf($token);
        foreach ($this->kinds() as $kind) {
            $record = $this->managers->forClass($kind)->find($kind, $tokenHash);
            if ($record !== null && ClientResolver::isResolved($record)) {
                return $record;
            }
        }

        return null;
    }

    public function revoke(StoredAccessToken $token): void
    {
        $this->remove([$token]);
    }

    public function revokeByGrant(Uuid $grantId): array
    {
        return $this->removeMatching([
            'grantId' => $grantId,
        ]);
    }

    public function revokeBySession(Uuid $session): array
    {
        return $this->removeMatching([
            'session' => $session,
        ], StoredUserAccessToken::class);
    }

    public function revokeByConsent(Consent $consent): array
    {
        $tokens = [];
        foreach ($this->kindsUnder(StoredUserAccessToken::class) as $kind) {
            /** @var list<StoredAccessToken> $ofThatKind */
            $ofThatKind = $this->managers
                ->forClass($kind)
                ->createQueryBuilder()
                ->select('t')
                ->from($kind, 't')
                ->join('t.session', 's')
                ->where('s.user = :user')
                ->andWhere('t.clientId = :clientId')
                ->setParameter('user', $consent->user->id, UuidType::NAME)
                ->setParameter('clientId', $consent->clientId)
                ->getQuery()
                ->getResult();
            $tokens = array_merge($tokens, $ofThatKind);
        }

        return $this->removeAll($tokens);
    }

    /**
     * @param array<string, mixed> $criteria
     * @param class-string<StoredAccessToken> $of
     *
     * @return list<StoredAccessToken> oldest first, those of an unregistered client left out
     */
    private function removeMatching(array $criteria, string $of = StoredAccessToken::class): array
    {
        $tokens = [];
        foreach ($this->kindsUnder($of) as $kind) {
            $tokens = array_merge($tokens, $this->managers
                ->forClass($kind)
                ->getRepository($kind)
                ->findBy($criteria, [
                    'issuedAt' => 'ASC',
                    'tokenHash' => 'ASC',
                ]));
        }

        return $this->removeAll($tokens);
    }

    /**
     * @param list<StoredAccessToken> $tokens
     *
     * @return list<StoredAccessToken> those this call removed, oldest first, those of an unregistered client left out
     */
    private function removeAll(array $tokens): array
    {
        usort($tokens, static fn (StoredAccessToken $a, StoredAccessToken $b): int => [$a->issuedAt, $a->tokenHash] <=> [$b->issuedAt, $b->tokenHash]);

        $removed = [];
        foreach ($tokens as $token) {
            if ($this->removeOnce($token) && ClientResolver::isResolved($token)) {
                $removed[] = $token;
            }
        }

        return $removed;
    }

    /**
     * Through the connection, not the unit of work, which deletes a row another worker deleted first without a word.
     */
    private function removeOnce(StoredAccessToken $token): bool
    {
        $manager = $this->managers->forClass($token::class);
        $metadata = $manager->getClassMetadata($token::class);
        $removed =
            $manager->getConnection()->executeStatement(
                sprintf('DELETE FROM %s WHERE %s = :tokenHash', $metadata->getTableName(), $metadata->getColumnName('tokenHash')),
                [
                    'tokenHash' => $token->tokenHash,
                ],
                [
                    'tokenHash' => ParameterType::STRING,
                ],
            ) === 1;
        $manager->detach($token);

        return $removed;
    }

    /**
     * @param class-string<StoredAccessToken> $of
     *
     * @return list<class-string<StoredAccessToken>>
     */
    private function kindsUnder(string $of): array
    {
        return array_values(array_filter(
            $this->kinds(),
            static fn (string $kind): bool => $kind === $of || is_subclass_of($kind, $of),
        ));
    }

    /**
     * @param list<StoredAccessToken> $tokens
     */
    private function remove(array $tokens): void
    {
        $managers = [];
        foreach ($tokens as $token) {
            $manager = $this->managers->forClass($token::class);
            $manager->remove($token);
            $managers[$token::class] = $manager;
        }
        foreach ($managers as $manager) {
            $manager->flush();
        }
    }

    /**
     * @return list<class-string<StoredAccessToken>>
     */
    private function kinds(): array
    {
        if ($this->kinds !== null) {
            return $this->kinds;
        }
        $kinds = [];
        foreach ($this->managers->all() as $manager) {
            foreach ($manager->getMetadataFactory()->getAllMetadata() as $metadata) {
                if ($metadata instanceof OrmClassMetadata && $metadata->isMappedSuperclass) {
                    continue;
                }
                $class = $metadata->getName();
                if (is_subclass_of($class, StoredAccessToken::class)) {
                    $kinds[] = $class;
                }
            }
        }
        sort($kinds);

        return $this->kinds = $kinds;
    }
}
