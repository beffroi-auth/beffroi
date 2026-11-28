<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use function array_column;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Event\JournalReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\SessionsReadByAnAdministrator;
use function is_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_replace;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0038: what the administration API of a tenant answers an administrator, read from what the commands of the
 * console read, and the act each read that delivers a person writes in the journal of that person, naming the
 * administrator who read them.
 */
final class AdministrationApiTest extends AdministrationTestCase
{
    #[Test]
    public function theTenantIsWhatTheDeploymentDeclares(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/tenant', $token);

        // Then
        $tenant = self::json($response);
        static::assertSame(
            [Response::HTTP_OK, 'https://op.test', ['administrators'], self::API],
            [$response->getStatusCode(), $tenant['issuer'] ?? null, $tenant['administrators'] ?? null, $tenant['administration_api'] ?? null],
        );
    }

    #[Test]
    public function theClientsOfTheTenantAreListed(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/clients', $token);

        // Then
        static::assertContains(self::CLIENT, array_column(self::listOf(self::json($response), 'clients'), 'client_id'));
    }

    #[Test]
    public function aClientTheDeploymentDeclaresIsShownWithoutARecord(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $client = self::json($this->api('/clients/' . self::CLIENT, $token));

        // Then
        static::assertSame([self::CLIENT, null], [$client['client_id'] ?? null, $client['metadata'] ?? null]);
    }

    #[Test]
    public function theSigningKeysAreListedWithTheirState(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/keys', $token);

        // Then
        static::assertSame(['active'], array_column(self::listOf(self::json($response), 'keys'), 'status'));
    }

    #[Test]
    public function aPersonIsReadByTheirUsernameWithTheirCredentialsAndGroups(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $person = self::json($this->api('/users', $token, query: ['username' => 'alice']));

        // Then
        static::assertSame(
            ['alice', ['passkey'], ['administrators']],
            [
                $person['username'] ?? null,
                array_column(self::listOf($person, 'credentials'), 'kind'),
                array_column(self::listOf($person, 'groups'), 'name'),
            ],
        );
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function aPersonIsReadWithTheChannelsTheyChose(): void
    {
        // Given
        $alice = self::user('alice');
        $alice->chooseChannels(new ChosenChannels(['mail'], ['pending_approval' => ['sms']]), self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
        $token = $this->administratorToken($alice);

        // When
        $person = self::json($this->api('/users', $token, query: ['username' => 'alice']));

        // Then
        static::assertSame(['every_kind' => ['mail'], 'set_apart' => ['pending_approval' => ['sms']]], $person['notification_channels'] ?? null);
    }

    #[Test]
    public function aPersonWhoChoseNothingIsReadWithNoChannelChosen(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $person = self::json($this->api('/users', $token, query: ['username' => 'alice']));

        // Then
        static::assertSame(['every_kind' => null, 'set_apart' => []], $person['notification_channels'] ?? null);
    }

    #[Test]
    public function theSessionsOfAPersonAreRead(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $id = self::string(self::json($this->api('/users', $token, query: ['username' => 'alice']))['id'] ?? null);

        // When
        $sessions = self::listOf(self::json($this->api(sprintf('/users/%s/sessions', $id), $token)), 'sessions');

        // Then
        static::assertContains('phrh', array_column($sessions, 'acr'));
    }

    /**
     * Decision 0031
     */
    #[Test]
    public function aSessionPastItsExpiryThatHasNotEndedIsRead(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $session = $this->signIn($bob, self::currentSecond()->modify('-13 hours'));
        $token = $this->administratorToken(self::user('alice'));

        // When
        $sessions = self::listOf(self::json($this->api(sprintf('/users/%s/sessions', $bob->id->toRfc4122()), $token)), 'sessions');

        // Then
        static::assertSame([$session->id->toRfc4122()], array_column($sessions, 'id'));
    }

    #[Test]
    public function theJournalOfAPersonIsRead(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        $id = self::string(self::json($this->api('/users', $token, query: ['username' => 'alice']))['id'] ?? null);

        // When
        $acts = self::listOf(self::json($this->api(sprintf('/users/%s/journal', $id), $token)), 'acts');

        // Then
        static::assertContains(UserAuthenticated::NAME, array_column($acts, 'act'));
    }

    /**
     * Decisions 0022 and 0038: each read that delivers a person is an act of theirs, naming the administrator.
     *
     * @param list<string> $reads the paths read, "{id}" standing for the identifier of the person read
     */
    #[Test]
    #[DataProvider('provideReadsOfAPerson')]
    public function aReadOfAPersonIsAnActOfTheirsNamingTheAdministrator(array $reads, string $act): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));
        $id = $bob->id->toRfc4122();

        // When
        foreach ($reads as $path) {
            $this->api(str_replace('{id}', $id, $path), $token, query: $path === '/users' ? ['username' => 'bob'] : []);
        }

        // Then
        $entry = self::entityManager()->getRepository(JournalEntry::class)->findOneBy(['act' => $act]);
        static::assertEquals(['bob-subject', new AnAdministrator(new Subject('alice-subject')), self::CLIENT], [
            $entry?->subject?->value,
            $entry?->author,
            $entry?->client,
        ]);
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function provideReadsOfAPerson(): iterable
    {
        yield 'the person' => [['/users'], PersonReadByAnAdministrator::NAME];
        yield 'their sessions' => [['/users/{id}/sessions'], SessionsReadByAnAdministrator::NAME];
        yield 'their journal' => [['/users/{id}/journal'], JournalReadByAnAdministrator::NAME];
    }

    /**
     * @param array<string, string> $query
     */
    #[Test]
    #[DataProvider('provideWhatTheTenantDoesNotHave')]
    public function whatTheTenantDoesNotHaveIsNotFound(string $path, array $query): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api($path, $token, query: $query);

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, 'not_found'], [$response->getStatusCode(), self::json($response)['error'] ?? null]);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideWhatTheTenantDoesNotHave(): iterable
    {
        yield 'a client' => ['/clients/nobody', []];
        yield 'a person by their username' => ['/users', ['username' => 'nobody']];
        yield 'the sessions of a person' => ['/users/0193b8d0-0000-7000-8000-000000000000/sessions', []];
        yield 'the journal of a person' => ['/users/0193b8d0-0000-7000-8000-000000000000/journal', []];
        yield 'a path the API does not serve' => ['/nothing/here', []];
    }

    #[Test]
    public function aPersonIsAskedForByTheirUsername(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/users', $token);

        // Then
        static::assertSame([Response::HTTP_BAD_REQUEST, 'invalid_request'], [$response->getStatusCode(), self::json($response)['error'] ?? null]);
    }

    #[Test]
    public function theHealthOfTheInstanceIsWhatTheDoctorLooksAt(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $checks = self::listOf(self::json($this->api('/health', $token)), 'checks');

        // Then
        static::assertNotSame([], array_column($checks, 'about'));
    }

    /**
     * One person, the two sessions she opened, the one she enrolled her passkey in and the one she signed in with,
     * and the signing key of the suite.
     */
    #[Test]
    public function theStatisticsCountWhatTheInstanceHolds(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $statistics = self::json($this->api('/statistics', $token));

        // Then
        static::assertSame(
            [1, 2, ['staged' => 0, 'active' => 1, 'retiring' => 0, 'retired' => 0]],
            [$statistics['users'] ?? null, $statistics['open_sessions'] ?? null, $statistics['keys'] ?? null],
        );
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @return list<array<string, mixed>>
     */
    private static function listOf(array $document, string $member): array
    {
        $list = $document[$member] ?? null;
        if (! is_array($list)) {
            static::fail(sprintf('The answer carries no "%s".', $member));
        }
        $items = [];
        foreach ($list as $item) {
            if (! is_array($item)) {
                static::fail(sprintf('An item of "%s" is not an object.', $member));
            }
            $members = [];
            foreach ($item as $name => $value) {
                $members[(string) $name] = $value;
            }
            $items[] = $members;
        }

        return $items;
    }
}
