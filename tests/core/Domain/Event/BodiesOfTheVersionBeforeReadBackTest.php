<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Event;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Domain\Event\GroupCreated;
use Beffroi\Core\Domain\Event\GroupMembershipAdded;
use Beffroi\Core\Domain\Event\GroupMembershipRemoved;
use Beffroi\Core\Domain\Event\PasswordTicketIssued;
use Beffroi\Core\Domain\Event\PersonCreated;
use Beffroi\Core\Domain\Event\PersonDescribed;
use Beffroi\Core\Domain\Event\PersonDisabled;
use Beffroi\Core\Domain\Event\PersonEnabled;
use Beffroi\Core\Domain\Event\TotpTicketIssued;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Ticket\PasswordTicket;
use Beffroi\Core\Domain\Ticket\TotpTicket;
use Beffroi\Core\Tests\Fixture\BodyOfTheVersionBefore;
use Beffroi\Core\Tests\Fixture\Fixtures;
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
        $user = Fixtures::user();
        $now = Fixtures::now();
        $ended = Fixtures::session($user);
        $ended->end(SessionEnd::User, $now);
        $passkey = Fixtures::passkey($user);
        $password = Fixtures::password($user);
        $events = [
            'a person created' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new PersonCreated($tenant, $user->subject, $now, $c, $a),
                new TheHost(),
            ],
            'a person disabled' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new PersonDisabled($tenant, $user->subject, $now, $c, $a),
                new TheHost(),
            ],
            'a person enabled' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new PersonEnabled($tenant, $user->subject, $now, $c, $a),
                new TheHost(),
            ],
            'a session ended' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new AuthenticationSessionEnded($ended, $now, $c, $a),
                new ThePerson(),
            ],
            'a credential revoked' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new CredentialRevoked($passkey, $now, $c, $a),
                new ThePerson(),
            ],
            'an enrolment ticket issued' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new EnrolmentTicketIssued(
                    new EnrolmentTicket(Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8091'), $user, $password->hash, $now, $now->modify('+72 hours')),
                    $now,
                    $c,
                    $a,
                ),
                new TheHost(),
            ],
            'a password ticket issued' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new PasswordTicketIssued(
                    new PasswordTicket(Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8092'), $user, $password->hash, $now, $now->modify('+72 hours')),
                    $now,
                    $c,
                    $a,
                ),
                new TheHost(),
            ],
            'a one-time password ticket issued' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new TotpTicketIssued(
                    new TotpTicket(Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8093'), $user, $password->hash, $now, $now->modify('+72 hours')),
                    $now,
                    $c,
                    $a,
                ),
                new TheHost(),
            ],
            'a group created' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new GroupCreated($tenant, 'auditors', $now, $c, $a),
                new TheHost(),
            ],
            'a member added' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new GroupMembershipAdded($tenant, $user->subject, 'auditors', $now, $c, $a),
                new TheHost(),
            ],
            'a member taken out' => [
                static fn (RequestContext $c, AuthorInterface $a): object => new GroupMembershipRemoved($tenant, $user->subject, 'auditors', $now, $c, $a),
                new TheHost(),
            ],
        ];
        $fromARequest = Fixtures::context();
        $fromTheConsole = Fixtures::context(ipAddress: null, userAgent: 'beffroi-console/beffroi:user:disable (operator@host)');
        foreach ($events as $name => [$event, $meant]) {
            yield $name . ', by an administrator' => [$event, $fromARequest, new AnAdministrator(new Subject('administrator-subject'))];
            yield $name . ', by nobody, from a request' => [$event, $fromARequest, $meant];
            yield $name . ', by nobody, from the console' => [$event, $fromTheConsole, new TheHost()];
        }
        yield 'a person described, by an administrator' => [
            static fn (RequestContext $c, AuthorInterface $a): object => new PersonDescribed($tenant, $user->subject, ['nickname'], $now, $c, $a),
            $fromARequest,
            new AnAdministrator(new Subject('administrator-subject')),
        ];
    }
}
