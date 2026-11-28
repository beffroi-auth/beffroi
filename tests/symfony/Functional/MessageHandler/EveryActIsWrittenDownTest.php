<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Load\LoadBudget;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
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
        static::assertSame(
            [PersonReadByAnAdministrator::NAME, 'bob-subject', 'alice-subject', 'administration-app'],
            [$act->act, $act->subject?->value, $act->author?->value, $act->client],
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
        static::assertSame('alice-subject', self::onlyAct()->author?->value);
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
        self::announce(new KmsUnavailable(self::now(), self::tenant(), self::context(), 'the vault did not answer'));

        // Then
        $act = self::onlyAct();
        static::assertSame([null, null], [$act->reason, $act->method]);
    }

    /**
     * Decision 0014, decision 0062
     *
     * @param non-empty-string $budget
     */
    #[Test]
    #[DataProvider('provideSpentBudgets')]
    public function aSpentLoadBudgetSaysWhichBudgetItSpent(string $budget, ?string $client): void
    {
        // When
        self::announce(new LoadBudgetSpent(self::now(), self::tenant(), self::context(), $budget, 'beffroi_protocol_token', $client));

        // Then
        static::assertSame($budget, self::onlyAct()->reason);
    }

    /**
     * @return iterable<string, array{non-empty-string, string|null}>
     */
    public static function provideSpentBudgets(): iterable
    {
        yield 'the budget of an origin' => [LoadBudget::ORIGIN, null];
        yield 'the budget of a client' => [LoadBudget::CLIENT, 'oidc-demo'];
    }

    /**
     * Decision 0014, decision 0062
     */
    #[Test]
    public function aSpentLoadBudgetNamesTheRouteItRefused(): void
    {
        // When
        self::announce(new LoadBudgetSpent(self::now(), self::tenant(), self::context(), LoadBudget::ORIGIN, 'beffroi_protocol_jwks', null));

        // Then
        static::assertSame('beffroi_protocol_jwks', self::onlyAct()->method);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aSpentLoadBudgetNamesTheClientThatSpentIt(): void
    {
        // When
        self::announce(new LoadBudgetSpent(self::now(), self::tenant(), self::context(), LoadBudget::CLIENT, 'beffroi_protocol_token', 'oidc-demo'));

        // Then
        static::assertSame('oidc-demo', self::onlyAct()->client);
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
