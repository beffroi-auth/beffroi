<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4
 */
final class CredentialRevocationTest extends TestCase
{
    private InMemoryCredentialRepository $credentials;

    private RecordingEventDispatcher $events;

    private RecordingCredentialChangeNotifier $notifier;

    private MockClock $clock;

    private CredentialRevocation $revocation;

    protected function setUp(): void
    {
        $this->credentials = new InMemoryCredentialRepository();
        $this->events = new RecordingEventDispatcher();
        $this->notifier = new RecordingCredentialChangeNotifier();
        $this->clock = new MockClock('2026-09-19T12:00:00+00:00');
        $this->revocation = new CredentialRevocation($this->credentials, $this->clock, $this->events, $this->notifier);
    }

    #[Test]
    public function aRevokedPasskeyStaysListedAndIsAnnounced(): void
    {
        // Given
        $alice = Fixtures::user();
        $passkey = Fixtures::passkey($alice);
        $this->credentials->save($passkey);
        $context = Fixtures::context($this->clock->now());

        // When
        $this->revocation->revoke($passkey, new ThePerson(), $context);

        // Then
        static::assertEquals($this->clock->now(), $passkey->revokedAt);
        static::assertSame([$passkey], $this->credentials->findByUser($alice, PasskeyCredential::class));
        $events = $this->events->of(CredentialRevoked::class);
        static::assertCount(1, $events);
        static::assertSame($passkey, $events[0]->credential);
        static::assertSame($context, $events[0]->context);
    }

    /**
     * NIST SP 800-63B-4 §4.5
     */
    #[Test]
    public function thePersonIsToldAPasskeyWasRemovedFromTheirAccount(): void
    {
        // Given
        $alice = Fixtures::user();
        $passkey = Fixtures::passkey($alice);
        $this->credentials->save($passkey);

        // When
        $this->revocation->revoke($passkey, new ThePerson(), Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([[CredentialRevoked::NAME, 'passkey']], $this->notifier->acts());
        static::assertEquals($this->clock->now(), $this->notifier->told[0]->occurredAt);
        static::assertTrue($alice->id->equals($this->notifier->told[0]->userId));
    }

    /**
     * NIST SP 800-63B-4 §4.5
     */
    #[Test]
    public function thePersonIsToldOfARevocationAnAdministratorMade(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $this->credentials->save($passkey);

        // When
        $this->revocation->revokeByAnAdministrator($passkey, new Subject('administrator-subject'), Fixtures::context());

        // Then
        static::assertSame([[CredentialRevoked::NAME, 'passkey']], $this->notifier->acts());
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theRevocationAnAdministratorMadeNamesThemInItsAct(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $this->credentials->save($passkey);
        $administrator = new Subject('administrator-subject');

        // When
        $this->revocation->revokeByAnAdministrator($passkey, $administrator, Fixtures::context());

        // Then
        static::assertEquals([true, new AnAdministrator($administrator)], [$passkey->isRevoked(), $this->events->of(CredentialRevoked::class)[0]->author()]);
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theRevocationNamesItsAuthorInItsAct(AuthorInterface $author): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $this->credentials->save($passkey);

        // When
        $this->revocation->revoke($passkey, $author, Fixtures::context());

        // Then
        static::assertSame($author, $this->events->of(CredentialRevoked::class)[0]->author());
    }

    /**
     * @return iterable<string, array{AuthorInterface}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the person' => [new ThePerson()];
        yield 'the host' => [new TheHost()];
    }

    #[Test]
    public function aSecondRevocationAnnouncesNothing(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $first = Fixtures::now();
        $passkey->revoke($first);
        $this->credentials->save($passkey);

        // When
        $this->revocation->revoke($passkey, new ThePerson(), Fixtures::context());

        // Then
        static::assertSame($first, $passkey->revokedAt);
        static::assertSame([], $this->events->events);
    }

    #[Test]
    public function aSecondRevocationTellsThePersonNothing(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $passkey->revoke(Fixtures::now());
        $this->credentials->save($passkey);

        // When
        $this->revocation->revoke($passkey, new ThePerson(), Fixtures::context());

        // Then
        static::assertSame([], $this->notifier->told);
    }
}
