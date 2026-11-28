<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Application\Identity\MailEncryptionChoice;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Event\PersonDescribedThemselves;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\MailEncryptionRefusedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class MailEncryptionChoiceTest extends TestCase
{
    private InMemoryUserRepository $users;

    private InMemoryClaimHistory $history;

    private RecordingEventDispatcher $events;

    private WritesAsTheyCome $writes;

    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->history = new InMemoryClaimHistory();
        $this->events = new RecordingEventDispatcher();
        $this->writes = new WritesAsTheyCome();
    }

    #[Test]
    public function theKeyAPersonGivesIsWhatTheirMailIsEncryptedTo(): void
    {
        // Given
        $user = self::verified();
        $key = self::key('9F2C');

        // When
        $this->choice()->choose($user, $key, Fixtures::context());

        // Then
        static::assertSame($key, $this->users->find($user->id)?->mailEncryption);
    }

    #[Test]
    public function theHistoryKeepsTheFormatAndTheFingerprintOfWhatWasGivenInPlaceOfWhatWasThere(): void
    {
        // Given
        $user = self::verified();
        $user->encryptMailTo(self::key('9F2C'), Fixtures::now());

        // When
        $this->choice()->choose($user, self::key('51AB'), Fixtures::context());

        // Then
        $changes = $this->history->lastOf($user, 10);
        static::assertCount(1, $changes);
        static::assertSame(MailEncryptionChoice::CHANGED, $changes[0]->claim);
        static::assertSame('smime 9F2C', $changes[0]->was);
        static::assertSame('smime 51AB', $changes[0]->became);
        static::assertEquals(new ThePerson(), $changes[0]->author);
    }

    #[Test]
    public function theChoiceAndItsHistoryLineAreWrittenInOneUnit(): void
    {
        // Given
        $user = self::verified();

        // When
        $this->choice()->choose($user, self::key('9F2C'), Fixtures::context());

        // Then
        static::assertSame(1, $this->writes->units);
    }

    #[Test]
    public function takingTheKeyBackIsAChangeToNothing(): void
    {
        // Given
        $user = self::verified();
        $user->encryptMailTo(self::key('9F2C'), Fixtures::now());

        // When
        $this->choice()->choose($user, null, Fixtures::context());

        // Then
        static::assertNull($user->mailEncryption);
        static::assertNull($this->history->lastOf($user, 10)[0]->became);
    }

    #[Test]
    public function theKeyGivenAgainIsNoChange(): void
    {
        // Given
        $user = self::verified();
        $user->encryptMailTo(self::key('9F2C'), Fixtures::now());

        // When
        $this->choice()->choose($user, self::key('9F2C'), Fixtures::context());

        // Then
        static::assertSame([], $this->history->lastOf($user, 10));
    }

    #[Test]
    public function theChoiceIsAnActOfThePersonThatNamesWhatChanged(): void
    {
        // Given
        $user = self::verified();

        // When
        $this->choice()->choose($user, self::key('9F2C'), Fixtures::context());

        // Then
        $announced = $this->events->of(PersonDescribedThemselves::class);
        static::assertCount(1, $announced);
        static::assertSame(MailEncryptionChoice::CHANGED, $announced[0]->claim);
        static::assertFalse($announced[0]->takenBack);
    }

    #[Test]
    public function aRefusedKeyWritesNothing(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        try {
            $this->choice()->choose($user, self::key('9F2C'), Fixtures::context());
        } catch (MailEncryptionRefusedException) {
        }

        // Then
        static::assertNull($this->users->find($user->id));
        static::assertSame([], $this->history->lastOf($user, 10));
        static::assertSame([], $this->events->of(PersonDescribedThemselves::class));
    }

    private function choice(): MailEncryptionChoice
    {
        return new MailEncryptionChoice($this->users, $this->history, $this->writes, $this->events, new MockClock(Fixtures::now()));
    }

    private static function verified(): User
    {
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());

        return $user;
    }

    private static function key(string $fingerprint): MailEncryptionKey
    {
        return new MailEncryptionKey(
            'smime',
            'material',
            $fingerprint,
            [new EmailAddress('alice@acme.example')],
            new DateTimeImmutable('2020-01-01'),
            new DateTimeImmutable('2030-01-01'),
        );
    }
}
