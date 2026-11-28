<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use App\Administration\AdministrationAnswer;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Domain\Event\PersonCreated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0026 and 0038: an administrator creates a person and issues the enrolment ticket that lets them pose a
 * passkey, through the administration API on the use cases of the commands of the console, each an act of the person
 * that names the administrator.
 */
final class AdministrationApiEnrolmentTest extends AdministrationTestCase
{
    #[Test]
    public function anAdministratorCreatesAPersonWhoHoldsNoCredential(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/users', $token, method: 'POST', content: '{"username": "dave", "email": "dave@example.com"}');

        // Then
        $dave = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findByUsername(self::tenant(), 'dave') ?? static::fail('Dave is not stored.');
        static::assertSame(
            [Response::HTTP_CREATED, $dave->id->toRfc4122(), 'dave', ['email' => 'dave@example.com', 'email_verified' => false], []],
            [$response->getStatusCode(), ...self::members($response, ['id', 'username', 'claims', 'credentials'])],
        );
    }

    /**
     * Decision 0022.
     */
    #[Test]
    public function theCreationIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api('/users', $token, method: 'POST', content: '{"username": "dave"}');

        // Then
        $dave = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findByUsername(self::tenant(), 'dave') ?? static::fail('Dave is not stored.');
        static::assertSame([[$dave->subject->value, 'alice-subject']], self::authored(PersonCreated::NAME));
    }

    #[Test]
    public function aUsernameTheTenantHoldsAlreadyIsAConflict(): void
    {
        // Given
        self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/users', $token, method: 'POST', content: '{"username": "bob"}');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, 'conflict', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(PersonCreated::NAME),
        ]);
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function noPersonIsCreatedWhileTheUsernamesOfTheTenantAreNotAllComparedByTheirForm(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));
        self::entityManager()
            ->getConnection()
            ->executeStatement('DELETE FROM ' . BlindIndexDerivations::TABLE);

        // When
        $response = $this->api('/users', $token, method: 'POST', content: '{"username": "bob"}');

        // Then
        static::assertSame([Response::HTTP_SERVICE_UNAVAILABLE, 'temporarily_unavailable', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(PersonCreated::NAME),
        ]);
    }

    #[Test]
    #[DataProvider('provideRequestsThatNameNoPerson')]
    public function aRequestThatNamesNoPersonCreatesNobody(string $content, string $contentType): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api('/users', $token, method: 'POST', content: $content, contentType: $contentType);

        // Then
        static::assertSame([Response::HTTP_BAD_REQUEST, 'invalid_request', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(PersonCreated::NAME),
        ]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRequestsThatNameNoPerson(): iterable
    {
        yield 'a form' => ['username=dave', 'application/x-www-form-urlencoded'];
        yield 'no JSON' => ['{"username": "dave"', 'application/json'];
        yield 'no username' => ['{"email": "dave@example.com"}', 'application/json'];
        yield 'a username that is no string' => ['{"username": 7}', 'application/json'];
        yield 'an empty username' => ['{"username": " "}', 'application/json'];
        yield 'a username RFC 8265 §3.3 refuses' => ['{"username": "dave\\ud83d\\ude42"}', 'application/json'];
        yield 'an address that is no email address' => ['{"username": "dave", "email": "dave"}', 'application/json'];
        yield 'an address verified that is not given' => ['{"username": "dave", "email_verified": true}', 'application/json'];
        yield 'a verification that is no boolean' => ['{"username": "dave", "email": "dave@example.com", "email_verified": "true"}', 'application/json'];
    }

    /**
     * Decision 0026.
     */
    #[Test]
    public function theLinkOfTheTicketAnAdministratorIssuedOpensThePageOfThatEnrolment(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode());
        $this->browser->request('GET', self::pathOf($response));
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function theAnswerSaysUntilWhenTheLinkOpens(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        self::reload();
        $tickets = self::entityManager()->getRepository(EnrolmentTicket::class)->findAll();
        static::assertCount(1, $tickets);
        static::assertSame([AdministrationAnswer::moment($tickets[0]->expiresAt)], self::members($response, ['expires_at']));
    }

    #[Test]
    public function theIssuingIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(EnrolmentTicketIssued::NAME));
    }

    /**
     * Decision 0026.
     */
    #[Test]
    public function aSecondTicketTakesTheFirstAway(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));
        $first = self::pathOf($this->api(self::ticketPath($bob), $token, method: 'POST'));

        // When
        $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        $this->browser->request('GET', $first);
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aPersonTheTenantDoesNotHoldGetsNoTicket(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(sprintf('/users/%s/enrolment-ticket', Uuid::v7()->toRfc4122()), $token, method: 'POST');

        // Then
        static::assertSame([Response::HTTP_NOT_FOUND, 'not_found', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(EnrolmentTicketIssued::NAME),
        ]);
    }

    #[Test]
    public function aDisabledAccountGetsNoTicket(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $bob->disable(self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($bob);
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(self::ticketPath($bob), $token, method: 'POST');

        // Then
        static::assertSame([Response::HTTP_CONFLICT, 'conflict', []], [
            $response->getStatusCode(),
            self::error($response),
            self::authored(EnrolmentTicketIssued::NAME),
        ]);
    }

    private static function ticketPath(User $person): string
    {
        return sprintf('/users/%s/enrolment-ticket', $person->id->toRfc4122());
    }

    /**
     * The path of the link a ticket was answered with, under the origin of the issuer.
     */
    private static function pathOf(Response $response): string
    {
        [$link] = self::members($response, ['link']);
        static::assertIsString($link);
        static::assertTrue(str_starts_with($link, self::ISSUER . '/enrol/'), sprintf('The link %s is not under %s/enrol/.', $link, self::ISSUER));

        return substr($link, strlen(self::ISSUER));
    }

    private static function error(Response $response): mixed
    {
        return self::members($response, ['error'])[0];
    }
}
