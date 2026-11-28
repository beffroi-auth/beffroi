<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use App\Administration\Controller\UserDescriptionController;
use function array_map;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Event\PersonDescribed;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038, RFC 7396: an administrator changes what the account of a person says through the administration API,
 * by a merge patch of the document a read of the person answers, each change a row of the history of the person and
 * the patch an act of theirs, both naming the administrator.
 */
final class AdministrationApiDescriptionTest extends AdministrationTestCase
{
    #[Test]
    public function aPatchChangesWhatTheAccountSaysAndAnswersIt(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->patch($bob, $token, '{"username": "robert", "claims": {"given_name": "Robert", "email": "robert@example.com"}}');

        // Then
        static::assertSame(
            [Response::HTTP_OK, 'robert', ['given_name' => 'Robert', 'email' => 'robert@example.com', 'email_verified' => false]],
            [$response->getStatusCode(), ...self::members($response, ['username', 'claims'])],
        );
    }

    #[Test]
    public function eachChangeIsARowOfTheHistoryOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->patch($bob, $token, '{"claims": {"nickname": "Bobby"}}');

        // Then
        static::assertEquals(
            [['nickname', null, 'Bobby', new AnAdministrator(new Subject('alice-subject'))]],
            array_map(
                static fn (ClaimChange $change): array => [$change->claim, $change->was, $change->became, $change->author],
                self::service('test.beffroi.changes', ChangesOfAPersonInterface::class)->lastOf(self::personAgain($bob), 10),
            ),
        );
    }

    #[Test]
    public function thePatchIsAnActOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->patch($bob, $token, '{"claims": {"nickname": "Bobby", "family_name": "Martin"}}');

        // Then
        static::assertSame([['bob-subject', 'alice-subject']], self::authored(PersonDescribed::NAME));
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function aPatchThatChangesNothingIsAReadOfThePersonThatNamesTheAdministrator(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->patch($bob, $token, '{"username": "bob"}');

        // Then
        static::assertSame(
            [[['bob-subject', 'alice-subject']], []],
            [self::authored(PersonReadByAnAdministrator::NAME), self::authored(PersonDescribed::NAME)],
        );
    }

    #[Test]
    public function aPatchThatChangesSomethingIsNoReadOfThePerson(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $this->patch($bob, $token, '{"claims": {"nickname": "Bobby"}}');

        // Then
        static::assertSame([], self::authored(PersonReadByAnAdministrator::NAME));
    }

    #[Test]
    public function aBodyThatIsNotAMergePatchChangesNothing(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->patch($bob, $token, '{"claims": {"nickname": "Bobby"}}', 'application/json');

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'invalid_request', null],
            [$response->getStatusCode(), self::members($response, ['error'])[0], self::personAgain($bob)->profile->nickname],
        );
    }

    #[Test]
    public function aMemberOfTheDocumentNoPatchChangesIsRefused(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->patch($bob, $token, '{"enabled": false}');

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'invalid_request', 'A patch changes the "username" and the "claims" of a person, not "enabled".'],
            [$response->getStatusCode(), ...self::members($response, ['error', 'error_description'])],
        );
    }

    #[Test]
    public function aValueRefusedChangesNothingElseThePatchSaid(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->patch($bob, $token, '{"claims": {"nickname": "Bobby", "birthdate": "the first of May"}}');

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, null, []],
            [$response->getStatusCode(), self::personAgain($bob)->profile->nickname, self::authored(PersonDescribed::NAME)],
        );
    }

    #[Test]
    public function aUsernameAnotherPersonOfTheTenantHasIsAConflict(): void
    {
        // Given
        $bob = self::user('bob', 'bob-subject');
        self::user('carol', 'carol-subject');
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->patch($bob, $token, '{"username": "carol"}');

        // Then
        static::assertSame(
            [Response::HTTP_CONFLICT, 'conflict', 'bob'],
            [$response->getStatusCode(), self::members($response, ['error'])[0], self::personAgain($bob)->username],
        );
    }

    #[Test]
    public function aPersonTheTenantDoesNotHoldIsNotFound(): void
    {
        // Given
        $token = $this->administratorToken(self::user('alice'));

        // When
        $response = $this->api(
            sprintf('/users/%s', Uuid::v7()->toRfc4122()),
            $token,
            method: 'PATCH',
            content: '{"claims": {"nickname": "Bobby"}}',
            contentType: UserDescriptionController::MERGE_PATCH,
        );

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, 'not_found', []],
            [$response->getStatusCode(), self::members($response, ['error'])[0], self::authored(PersonDescribed::NAME)],
        );
    }

    private function patch(User $person, string $token, string $patch, string $contentType = UserDescriptionController::MERGE_PATCH): Response
    {
        return $this->api(
            sprintf('/users/%s', $person->id->toRfc4122()),
            $token,
            method: 'PATCH',
            content: $patch,
            contentType: $contentType,
        );
    }
}
