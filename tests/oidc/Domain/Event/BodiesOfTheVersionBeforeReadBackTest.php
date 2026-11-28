<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Event;

use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Tests\Fixture\BodyOfTheVersionBefore;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Event\ConsentRevoked;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenIssued;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenRevoked;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function unserialize;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0066: an event a queue held when the provider was upgraded, written by the version before acts named the
 * kind of their author, reads back naming the administrator it named, and, naming nobody, the host when it came from no
 * address and the author its callers meant otherwise.
 */
final class BodiesOfTheVersionBeforeReadBackTest extends TestCase
{
    /**
     * @param Closure(RequestContext, AuthorInterface): object $event
     */
    #[Test]
    #[DataProvider('provideEvents')]
    public function anEventTheVersionBeforeWroteReadsBackNamingItsAuthor(Closure $event, RequestContext $context, AuthorInterface $author): void
    {
        // Given
        $written = $event($context, $author);

        // When
        $read = unserialize(BodyOfTheVersionBefore::of($written));

        // Then
        static::assertEquals($written, $read);
    }

    /**
     * @return iterable<string, array{Closure(RequestContext, AuthorInterface): object, RequestContext, AuthorInterface}>
     */
    public static function provideEvents(): iterable
    {
        $tenant = Fixtures::tenant();
        $subject = Fixtures::user()->subject;
        $now = Fixtures::now();
        $id = Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8091');
        $events = [
            'a consent taken back' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new ConsentRevoked(
                    $now,
                    $tenant,
                    $id,
                    'oidc-demo',
                    $subject,
                    [$id],
                    ['refresh-hash'],
                    ['access-hash'],
                    $c,
                    $a,
                ),
                new ThePerson(),
            ],
            'an initial access token issued' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new InitialAccessTokenIssued($now, $tenant, $id, $c, $a),
                new TheHost(),
            ],
            'an initial access token revoked' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new InitialAccessTokenRevoked($now, $tenant, $id, $c, $a),
                new TheHost(),
            ],
            'a logout token issued' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new LogoutTokenIssued(
                    $now,
                    $tenant,
                    'oidc-demo',
                    $subject,
                    new ClientUri('https://demo.example/logout'),
                    $id,
                    'eyJ.the.token',
                    $c,
                    $a,
                ),
                new ThePerson(),
            ],
            'a logout token given up on' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new LogoutTokenGivenUp(
                    $now,
                    $tenant,
                    $c,
                    'oidc-demo',
                    $subject,
                    $id,
                    'the client answered 410',
                    $a,
                ),
                new ThePerson(),
            ],
            'a registered client deleted' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new RegisteredClientDeleted($now, $tenant, 'oidc-demo', $c, $a),
                new AClient('oidc-demo'),
            ],
        ];
        $fromARequest = Fixtures::context();
        $fromTheHost = Fixtures::context(ipAddress: null, userAgent: 'beffroi-scheduler/advance (host)');
        foreach ($events as $name => [$event, $meant]) {
            yield $name . ', by an administrator' => [$event, $fromARequest, new AnAdministrator(new Subject('administrator-subject'))];
            yield $name . ', by nobody, from a request' => [$event, $fromARequest, $meant];
            yield $name . ', by nobody, from the host' => [$event, $fromTheHost, new TheHost()];
        }
    }
}
