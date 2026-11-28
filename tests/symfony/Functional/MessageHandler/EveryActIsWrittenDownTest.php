<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Closure;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Event\PersonProvisioned;
use Beffroi\Core\Domain\Author\AnUpstreamProvider;
use Beffroi\Core\Domain\Author\AnUnauthenticatedCaller;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use Beffroi\Core\Domain\Event\PersonDisabled;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use function array_keys;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

final class EveryActIsWrittenDownTest extends DatabaseTestCase
{
    #[Test]
    public function anActThatConcernsAPersonNamesThem(): void
    {
        // Given
        $user = self::user('alice');
        $session = self::session($user, self::now());

        // When
        self::announce(new UserAuthenticated($session));

        // Then
        $act = self::onlyAct();
        static::assertSame(UserAuthenticated::NAME, $act->act);
        static::assertSame($user->subject->value, $act->subject?->value);
        static::assertNull($act->client);
    }

    /**
     * Decision 0038: an act an administrator did to a person names the person and, beside them, the administrator.
     */
    #[Test]
    public function anActSomebodyElseDidToAPersonNamesItsAuthor(): void
    {
        // Given
        $user = self::user('bob', 'bob-subject');

        // When
        self::announce(
            new PersonReadByAnAdministrator(self::now(), self::tenant(), 'administration-app', $user->subject, new Subject('alice-subject'), self::context()),
        );

        // Then
        $act = self::onlyAct();
        static::assertEquals(
            [PersonReadByAnAdministrator::NAME, 'bob-subject', new AnAdministrator(new Subject('alice-subject')), 'administration-app'],
            [$act->act, $act->subject?->value, $act->author, $act->client],
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function anActWhoseTenantCameBackFromAQueueNamesItsAuthor(): void
    {
        // Given
        $user = self::user('bob', 'bob-subject');
        $tenant = self::tenant();
        self::reload();

        // When
        self::announce(
            new PersonReadByAnAdministrator(self::now(), $tenant, 'administration-app', $user->subject, new Subject('alice-subject'), self::context()),
        );

        // Then
        static::assertEquals(new AnAdministrator(new Subject('alice-subject')), self::onlyAct()->author);
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theAuthorOfAnActIsWrittenAsTheDocumentOfTheirKindAndReadBackAsTheyWere(AuthorInterface $author, string $written): void
    {
        // Given
        $user = self::user('alice');

        // When
        self::announce(new PersonDisabled(self::tenant(), $user->subject, self::now(), self::context(), $author));

        // Then
        static::assertEquals([$written, $author], [self::connection()->fetchOne('SELECT author FROM beffroi_journal'), self::onlyAct()->author]);
    }

    /**
     * @return iterable<string, array{AuthorInterface, string}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the person' => [new ThePerson(), '{"kind":"person"}'];
        yield 'an administrator, by the subject of their account' => [
            new AnAdministrator(new Subject('mallory-subject')),
            '{"kind":"administrator","subject":"mallory-subject"}',
        ];
        yield 'a client, by its identifier' => [new AClient('oidc-demo'), '{"kind":"client","client_id":"oidc-demo"}'];
        yield 'a directory, by its name' => [new ADirectory('Entra ID'), '{"kind":"directory","name":"Entra ID"}'];
        yield 'the host' => [new TheHost(), '{"kind":"host"}'];
    }

    /**
     * Decision 0066: no act is written without its author.
     *
     * @param Closure(User, AuthenticationSession): DomainEventInterface $event
     */
    #[Test]
    #[DataProvider('provideActsOfEachAuthor')]
    public function anActNamesItsAuthor(Closure $event, AuthorInterface $author): void
    {
        // Given
        $user = self::user('alice');
        $session = self::session($user, self::now());

        // When
        self::announce($event($user, $session));

        // Then
        static::assertEquals($author, self::onlyAct()->author);
    }

    /**
     * @return iterable<string, array{Closure(User, AuthenticationSession): DomainEventInterface, AuthorInterface}>
     */
    public static function provideActsOfEachAuthor(): iterable
    {
        yield 'a sign-in, the person' => [
            static fn (User $user, AuthenticationSession $session): DomainEventInterface => new UserAuthenticated($session),
            new ThePerson(),
        ];
        yield 'a refused attempt, an unauthenticated caller' => [
            static fn (User $user, AuthenticationSession $session): DomainEventInterface => new AuthenticationFailed(
                self::now(),
                self::tenant(),
                self::context(),
                null,
                AuthenticationFailureReason::UnknownUser,
                'nobody',
                null,
            ),
            new AnUnauthenticatedCaller(),
        ];
        yield 'a person an upstream provider created, the provider' => [
            static fn (User $user, AuthenticationSession $session): DomainEventInterface => new PersonProvisioned(
                self::now(),
                self::tenant(),
                $user->subject,
                'Acme SSO',
                self::context(),
            ),
            new AnUpstreamProvider('Acme SSO'),
        ];
        yield 'a load refused to a client, the client' => [
            static fn (User $user, AuthenticationSession $session): DomainEventInterface => new LoadBudgetSpent(
                self::now(),
                self::tenant(),
                self::context(),
                'client',
                '/token',
                'oidc-demo',
            ),
            new AClient('oidc-demo'),
        ];
        yield 'a load refused before anybody was known, an unauthenticated caller' => [
            static fn (User $user, AuthenticationSession $session): DomainEventInterface => new LoadBudgetSpent(
                self::now(),
                self::tenant(),
                self::context(),
                'origin',
                '/jwks',
                null,
            ),
            new AnUnauthenticatedCaller(),
        ];
    }

    /**
     * Decision 0060: a row written before acts named the kind of their author is never rewritten, and reads back as it
     * was written.
     */
    #[Test]
    #[DataProvider('provideAuthorsWrittenBefore')]
    public function anActWrittenBeforeActsNamedTheKindOfTheirAuthorReadsBackAsItWasWritten(?string $written, ?AuthorInterface $read): void
    {
        // Given
        $user = self::user('alice');
        self::announce(new PersonDisabled(self::tenant(), $user->subject, self::now(), self::context(), new TheHost()));
        self::connection()->executeStatement('UPDATE beffroi_journal SET author = ?', [$written]);
        self::reload();

        // When
        $act = self::onlyAct();

        // Then
        static::assertEquals($read, $act->author);
    }

    /**
     * @return iterable<string, array{string|null, AuthorInterface|null}>
     */
    public static function provideAuthorsWrittenBefore(): iterable
    {
        yield 'an administrator, by their bare subject' => ['mallory-subject', new AnAdministrator(new Subject('mallory-subject'))];
        yield 'the person or the host, by nothing' => [null, null];
    }

    #[Test]
    public function anActThatNamesNobodyLeavesThatColumnEmpty(): void
    {
        // When
        self::announce(new LoadBudgetSpent(self::now(), self::tenant(), self::context(), 'origin', '/jwks', null));

        // Then
        $act = self::onlyAct();
        static::assertSame(LoadBudgetSpent::NAME, $act->act);
        static::assertNull($act->subject);
        static::assertNull($act->client);
    }

    #[Test]
    public function anActThatConcernsAClientNamesIt(): void
    {
        // Given
        $user = self::user('alice');

        // When
        self::announce(new ConsentGranted(
            self::now(),
            self::tenant(),
            Uuid::v7(),
            'oidc-demo',
            $user->subject,
            new Scopes([new Scope('openid')]),
            null,
            new ClaimNames(),
            null,
            self::context(),
        ));

        // Then
        $act = self::onlyAct();
        static::assertSame(ConsentGranted::NAME, $act->act);
        static::assertSame('oidc-demo', $act->client);
    }

    #[Test]
    public function anActSaysWhereItCameFrom(): void
    {
        // When
        self::announce(new AuthenticationFailed(
            self::now(),
            self::tenant(),
            self::context(),
            null,
            AuthenticationFailureReason::UnknownUser,
            'nobody',
            null,
        ));

        // Then
        $act = self::onlyAct();
        static::assertSame(SealedRows::IP_ADDRESS, $act->context->ipAddress);
        static::assertNull($act->subject, 'an authentication that failed on an identifier no account answers happened to nobody');
    }

    /**
     * Decision 0062
     */
    #[Test]
    public function aRefusalSaysWhyItRefusedAndTheMethodItRefused(): void
    {
        // When
        self::announce(new ClientAuthenticationFailed(
            self::now(),
            self::tenant(),
            self::context(),
            ClientAuthenticationFailureReason::InvalidSecret,
            'oidc-demo',
            'client_secret_basic',
        ));

        // Then
        $act = self::onlyAct();
        static::assertSame(['oidc-demo', 'invalid_secret', 'client_secret_basic'], [$act->client, $act->reason, $act->method]);
    }

    /**
     * Decision 0062
     */
    #[Test]
    public function aRefusalOfAClientTheTenantDoesNotHoldNamesNoClient(): void
    {
        // When
        self::announce(new ClientAuthenticationFailed(
            self::now(),
            self::tenant(),
            self::context(),
            ClientAuthenticationFailureReason::UnknownClient,
            null,
            'client_secret_post',
        ));

        // Then
        $act = self::onlyAct();
        static::assertSame([null, 'unknown_client', 'client_secret_post'], [$act->client, $act->reason, $act->method]);
    }

    #[Test]
    public function anActThatRefusedNothingSaysNoReason(): void
    {
        // When
        self::announce(new LoadBudgetSpent(self::now(), self::tenant(), self::context(), 'origin', '/jwks', null));

        // Then
        $act = self::onlyAct();
        static::assertSame([null, null], [$act->reason, $act->method]);
    }

    #[Test]
    public function theJournalHoldsTheFourFactsTheThreeNamesAndWhyARefusalRefusedAndNothingElse(): void
    {
        // When / Then
        static::assertSame(
            ['act', 'author', 'client', 'context', 'id', 'method', 'occurred_at', 'reason', 'subject', 'tenant_id'],
            array_keys(ClassifiedModel::of(self::entityManager())->linesOf('beffroi_journal')),
        );
    }

    private static function connection(): Connection
    {
        return self::service('doctrine.dbal.default_connection', Connection::class);
    }

    private static function counted(string $sql): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne($sql);
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }

    private static function onlyAct(): JournalEntry
    {
        static::assertSame(1, self::counted('SELECT COUNT(*) FROM beffroi_journal'));
        $id = self::connection()->fetchOne('SELECT id FROM beffroi_journal');
        static::assertIsString($id);

        return self::entityManager()->find(JournalEntry::class, Uuid::fromString($id)) ?? static::fail('The act was not written down.');
    }
}
