<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use function implode;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Doctrine\TenantSynchronizer;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use function sprintf;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionFactoryInterface;
use Symfony\Component\Uid\Uuid;
use function time;

/**
 * A browser on the kernel of this application (issue beffroi-auth/beffroi#521), which is the kernel a
 * deployment boots: its own configuration, its own routes, its own templates, PostgreSQL and the KMS that
 * seals the personal columns. What is judged here is what this application adds to the bundle; every rule
 * of the provider is judged by the three suites of the monorepo, on a kernel of their own.
 *
 * The schema is not created here. The migrations of the bundle write it, once, before the suite runs
 * ("castor app-phpunit"), as they write it on a deployment; what every test gets is a database emptied of
 * its rows and the tenant of the configuration synchronised again, so that a test starts where an
 * application starts after its first provisioning.
 */
abstract class BrowserTestCase extends WebTestCase
{
    protected KernelBrowser $browser;

    protected function setUp(): void
    {
        // Over TLS, as a deployment is served and as every request below reads it: the session cookie is
        // "__Host-" prefixed and the provider answers HSTS, neither of which a browser accepts on a plain
        // HTTP request, and "nelmio_security.forced_ssl" sends such a request back to HTTPS before a
        // controller ever sees it (config/packages/framework.yaml, config/packages/nelmio_security.yaml).
        $this->browser = static::createClient([], ['HTTPS' => 'on']);
        // One kernel for the whole test, where a KernelBrowser reboots one per request by default: a
        // service then keeps what it holds from one request to the next, which is what the provider does
        // in production (the same reason as the suite of the bundle, issue beffroi-auth/beffroi#510).
        $this->browser->disableReboot();
        self::emptyTheDatabase();
    }

    /**
     * Every row of every table but the one the migrations keep their own state in, and the tenant of the
     * configuration written again. Truncating is read from the schema and not from the mapping, because
     * the data keys a sealed column is sealed under are a table of symfony/key-management and not an
     * entity of this provider (decision 0018): a test that left them behind would hand the next one keys
     * minted for a tenant that no longer exists.
     */
    private static function emptyTheDatabase(): void
    {
        $connection = self::entityManager()->getConnection();
        $tables = [];
        foreach ($connection->createSchemaManager()->listTableNames() as $table) {
            if ($table !== 'doctrine_migration_versions') {
                $tables[] = $connection->quoteSingleIdentifier($table);
            }
        }
        $connection->executeStatement(sprintf('TRUNCATE TABLE %s CASCADE', implode(', ', $tables)));
        self::entityManager()->clear();
        self::service('test.beffroi.tenant_synchronizer', TenantSynchronizer::class)->synchronize();
    }

    /**
     * A user of the configured tenant, saved.
     */
    protected static function user(string $username = 'alice', string $subject = 'alice-subject'): User
    {
        $user = User::create(Uuid::v7(), self::tenant(), new Subject($subject), $username, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        return $user;
    }

    /**
     * A session of the user opened with a password, which the browser presents from its next request on,
     * the way the login of the firewall binds it.
     */
    protected function signIn(User $user): AuthenticationSession
    {
        $establishedAt = self::now();
        $session = new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            $establishedAt,
            AuthenticationProofs::of(AuthenticationMethod::password(), $establishedAt),
            new RequestContext($establishedAt, '127.0.0.1', 'Beffroi test browser'),
            $establishedAt->modify('+12 hours'),
        );
        self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->save($session);
        $httpSession = self::service('session.factory', SessionFactoryInterface::class)->createSession();
        $httpSession->start();
        self::service('test.beffroi.browser_session', BrowserSession::class)->bind($httpSession, $session);
        $httpSession->save();
        $this->browser->getCookieJar()->set(new Cookie($httpSession->getName(), $httpSession->getId()));

        return $session;
    }

    /**
     * The page a form of these pages comes back to (issue beffroi-auth/beffroi#522): every one of them
     * answers with a redirection a browser re-issues as a GET, so what a test reads after submitting is
     * the page that redirection names, and what was refused is on it.
     */
    protected function afterTheForm(): Crawler
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));

        return $this->browser->followRedirect();
    }

    /**
     * The user as the rows hold them now: the object a test created before its act is not the one the
     * request just served wrote.
     */
    protected static function reread(User $user): User
    {
        self::entityManager()->clear();

        return self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
    }

    /**
     * The tenant of the current unit of work.
     */
    protected static function tenant(): Tenant
    {
        return self::service('test.beffroi.tenant_provider', TenantProvider::class)->provide();
    }

    /**
     * The real now, with the precision of a datetime column.
     */
    protected static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . time());
    }

    protected static function string(mixed $value): string
    {
        static::assertIsString($value);

        return $value;
    }

    private static function entityManager(): EntityManagerInterface
    {
        return self::service('doctrine.orm.entity_manager', EntityManagerInterface::class);
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
        $service = static::getContainer()->get($id);
        static::assertInstanceOf($class, $service);

        return $service;
    }
}
