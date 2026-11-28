<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use App\Administration\Controller\UserDescriptionController;
use App\Administration\PersonsRefusalListener;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\ReadRefusedToAnAdministrator;
use Beffroi\Oidc\Port\PersonsBudgetInterface;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0014, the budget of the persons one administrator reads through the administration API; decisions 0022 and
 * 0038.
 */
final class AdministrationApiPersonsBudgetTest extends AdministrationTestCase
{
    /**
     * The smallest budget a deployment may set, the largest page of members.
     */
    private const int BUDGET = 100;

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_ADMINISTRATOR_PERSONS'] = (string) self::BUDGET;
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_ADMINISTRATOR_PERSONS'], $_ENV['BEFFROI_TEST_ADMINISTRATOR_PERSONS']);
    }

    /**
     * RFC 6585 §4, RFC 9110 §10.2.3
     */
    #[Test]
    public function anAdministratorPastTheirBudgetIsRefusedWithTheDelayBeforeTheNextRead(): void
    {
        // Given
        self::user('bob', 'bob-subject');
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $this->spend($alice, self::BUDGET);

        // When
        $response = $this->api('/users', $token, query: ['username' => 'bob']);

        // Then
        $retryAfter = (int) $response->headers->get('Retry-After');
        static::assertSame(
            [Response::HTTP_TOO_MANY_REQUESTS, true, true, [null, sprintf(PersonsRefusalListener::DESCRIPTION, $retryAfter)]],
            [
                $response->getStatusCode(),
                $retryAfter > 0,
                $response->headers->hasCacheControlDirective('no-store'),
                self::members($response, ['error', 'error_description']),
            ],
        );
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function aReadPastTheBudgetDeliversNobody(): void
    {
        // Given
        self::user('bob', 'bob-subject');
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $this->spend($alice, self::BUDGET);

        // When
        $this->api('/users', $token, query: ['username' => 'bob']);

        // Then
        static::assertSame([], self::authored(PersonReadByAnAdministrator::NAME));
    }

    #[Test]
    public function theRefusalIsAnActInTheJournalOfTheAdministrator(): void
    {
        // Given
        self::user('bob', 'bob-subject');
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $this->spend($alice, self::BUDGET);

        // When
        $this->api('/users', $token, query: ['username' => 'bob']);

        // Then
        static::assertSame(
            [['alice-subject', null, self::CLIENT]],
            array_map(
                static fn (JournalEntry $act): array => [$act->subject?->value, $act->author, $act->client],
                self::entityManager()->getRepository(JournalEntry::class)->findBy(['act' => ReadRefusedToAnAdministrator::NAME]),
            ),
        );
    }

    #[Test]
    public function aPageOfMembersSpendsOnePersonForEachMember(): void
    {
        // Given
        $auditors = new Group(Uuid::v7(), self::tenant(), 'auditors', GroupSource::Local, Clock::get()->now());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($auditors);
        foreach (['bob', 'carol'] as $username) {
            self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class)
                ->save(
                    new GroupMembership(Uuid::v7(), $auditors, self::user($username, $username . '-subject'), GroupSource::Local, Clock::get()->now()),
                );
        }
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $this->spend($alice, self::BUDGET - 2);
        $this->api(sprintf('/groups/%s/members', $auditors->id->toRfc4122()), $token);

        // When
        $response = $this->api('/users', $token, query: ['username' => 'bob']);

        // Then
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
    }

    #[Test]
    public function aReadWithinTheBudgetIsServed(): void
    {
        // Given
        self::user('bob', 'bob-subject');
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $this->spend($alice, self::BUDGET - 1);

        // When
        $response = $this->api('/users', $token, query: ['username' => 'bob']);

        // Then
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
    }

    /**
     * A change answered with the person it changed delivers them as a read does: an empty patch would read a person
     * otherwise.
     *
     * @param array{string, string, ?string, string} $request the method, the path after the person, the body and its type
     */
    #[Test]
    #[DataProvider('provideChangesAnsweredWithThePerson')]
    public function aChangeAnsweredWithThePersonIsRefusedPastTheBudget(array $request): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $this->spend($alice, self::BUDGET);
        [$method, $after, $content, $type] = $request;

        // When
        $response = $this->api(sprintf('/users/%s%s', $bob->id->toRfc4122(), $after), $token, method: $method, content: $content, contentType: $type);

        // Then
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
    }

    /**
     * @return iterable<string, array{array{string, string, ?string, string}}>
     */
    public static function provideChangesAnsweredWithThePerson(): iterable
    {
        yield 'an empty patch' => [['PATCH', '', '{}', UserDescriptionController::MERGE_PATCH]];
        yield 'the account disabled' => [['PUT', '/disabled', null, 'application/json']];
        yield 'the account enabled again' => [['DELETE', '/disabled', null, 'application/json']];
    }

    /**
     * Decision 0022: a credential revoked already is answered as it is, a read of the person.
     */
    #[Test]
    public function aCredentialRevokedAlreadyIsRefusedPastTheBudget(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $passkey = $this->enrol($bob, self::device());
        $alice = self::user('alice');
        $token = $this->administratorToken($alice);
        $path = sprintf('/users/%s/credentials/%s', $bob->id->toRfc4122(), $passkey->id->toRfc4122());
        $this->api($path, $token, method: 'DELETE');
        $this->spend($alice, self::BUDGET);

        // When
        $response = $this->api($path, $token, method: 'DELETE');

        // Then
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
    }

    /**
     * The persons spent from the budget of the administrator in the kernel of the API, as reads would have.
     */
    private function spend(User $administrator, int $persons): void
    {
        $this->administrationService('test.beffroi.persons_budget', PersonsBudgetInterface::class)->spend(
            new ActingAdministrator($administrator->tenant, $administrator, self::CLIENT, Uuid::v7()),
            $persons,
        );
    }
}
