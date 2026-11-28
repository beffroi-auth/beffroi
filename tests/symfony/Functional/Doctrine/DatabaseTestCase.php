<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Closure;
use function copy;
use DateTimeImmutable;
use Doctrine\DBAL\Types\TypeProvider;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\Persistence\ManagerRegistry;
use App\Doctrine\TenantProvider;
use App\Doctrine\EntityManagers;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Doctrine\TenantSynchronizer;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Application\Tenant\TenantHardening;
use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use function is_string;
use function sprintf;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §7
 */
abstract class DatabaseTestCase extends WebTestCase
{
    protected function setUp(): void
    {
        self::bootKernel();
        self::prepareDatabase();
    }

    /**
     * @param (Closure(ContainerInterface): void)|null $configureContainer reapplied at every kernel reboot
     * @param array<string, mixed> $options
     */
    protected static function browser(?Closure $configureContainer = null, array $options = []): KernelBrowser
    {
        self::ensureKernelShutdown();
        $browser = self::createClient(
            $configureContainer === null
                ? $options
                : [
                    ...$options,
                    'configure_container' => $configureContainer,
                ],
        );
        self::prepareDatabase();

        return $browser;
    }

    /**
     * @var array<string, string> the template of each database file
     */
    private static array $templates = [];

    protected static function keyStorage(): string
    {
        return self::cacheDirectory() . '/keys';
    }

    protected static function metadataStorage(): string
    {
        return self::cacheDirectory() . '/webauthn';
    }

    private static function cacheDirectory(): string
    {
        $cacheDirectory = static::getContainer()->getParameter('kernel.cache_dir');
        if (! is_string($cacheDirectory)) {
            static::fail('The cache directory of the test kernel is not a path.');
        }

        return $cacheDirectory;
    }

    private static function prepareDatabase(): void
    {
        $connection = self::entityManager()->getConnection();
        $connection->close();
        $database = static::getContainer()->getParameter('beffroi_test.database');
        if (! is_string($database)) {
            static::fail('The database of the test kernel is not a file.');
        }
        $template = self::$templates[$database] ?? null;
        if ($template === null) {
            self::createDatabase();
            $connection->close();
            $template = self::$templates[$database] = $database . '.template';
            copy($database, $template) || static::fail('The template of the database was not written.');
        } else {
            copy($template, $database) || static::fail('The database was not restored from its template.');
        }
        self::entityManager()->clear();
    }

    private static function createDatabase(): void
    {
        $entityManager = self::entityManager();
        $schema = new SchemaTool($entityManager);
        $entityManager->wrapInTransaction(static function () use ($entityManager, $schema): void {
            $schema->dropDatabase();
            $schema->createSchema($entityManager->getMetadataFactory()->getAllMetadata());
        });
        self::service('test.beffroi.tenant_synchronizer', TenantSynchronizer::class)->synchronize();
    }

    protected static function entityManager(): EntityManagerInterface
    {
        return self::service('doctrine.orm.entity_manager', EntityManagerInterface::class);
    }

    protected static function typesOfTheConnection(): TypeProvider
    {
        return self::entityManager()->getConnection()->getConfiguration()->getTypeProvider();
    }

    protected static function registry(): ManagerRegistry
    {
        return self::service('doctrine', ManagerRegistry::class);
    }

    protected static function managers(): EntityManagers
    {
        return new EntityManagers(self::registry());
    }

    protected static function derivations(): BlindIndexDerivations
    {
        return self::service(BlindIndexDerivations::class, BlindIndexDerivations::class);
    }

    protected static function tenant(): Tenant
    {
        return self::service('test.beffroi.tenant_provider', TenantProvider::class)->provide();
    }

    /**
     * @return int how many credentials the floor forbade
     */
    protected static function harden(AuthenticationPredicateInterface $floor): int
    {
        return self::service('test.beffroi.tenant_hardening', TenantHardening::class)->adopt(self::tenant(), $floor, self::context());
    }

    protected static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-09-15T10:00:00+00:00');
    }

    protected static function context(?DateTimeImmutable $receivedAt = null): RequestContext
    {
        return new RequestContext($receivedAt ?? self::now(), SealedRows::IP_ADDRESS, SealedRows::USER_AGENT);
    }

    protected static function user(string $username = 'alice', string $subject = 'alice-subject'): User
    {
        $user = User::create(Uuid::v7(), self::tenant(), new Subject($subject), $username, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        return $user;
    }

    protected static function session(User $user, ?DateTimeImmutable $establishedAt = null): AuthenticationSession
    {
        $establishedAt ??= self::now();
        $session = new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            $establishedAt,
            AuthenticationProofs::of(AuthenticationMethod::password(), $establishedAt),
            self::context($establishedAt),
            $establishedAt->modify('+12 hours'),
        );
        self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->save($session);

        return $session;
    }

    protected static function client(string $clientId = 'oidc-demo'): Client
    {
        return (
            self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId) ?? static::fail(sprintf(
                'The client "%s" is not configured.',
                $clientId,
            ))
        );
    }

    protected static function reload(): void
    {
        self::entityManager()->clear();
    }

    /**
     * The person as the store holds them now, read past what the test's own manager remembers.
     */
    protected static function personAgain(User $person): User
    {
        self::reload();

        return self::service('test.beffroi.users', UserRepositoryInterface::class)->find($person->id) ?? static::fail('The person is gone.');
    }

    /**
     * The session as the store holds it now, read past what the test's own manager remembers.
     */
    protected static function sessionAgain(AuthenticationSession $session): AuthenticationSession
    {
        self::reload();

        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id) ?? static::fail('The session is gone.')
        );
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    protected static function service(string $id, string $class): object
    {
        $service = self::getContainer()->get($id);
        static::assertInstanceOf($class, $service);

        return $service;
    }
}
