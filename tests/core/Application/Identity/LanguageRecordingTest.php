<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\LanguageRecording;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #471: the language a person told this provider they read, written on their account. It is the one
 * claim this provider needs in order to write to them at all (UserLocale, architecture §5.7).
 */
final class LanguageRecordingTest extends TestCase
{
    #[Test]
    public function theLanguageIsWrittenOnTheAccount(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = self::user($users);

        // When
        new LanguageRecording($users, new MockClock(Fixtures::now()))->record($user, 'fr');

        // Then
        static::assertSame('fr', $users->find($user->id)?->profile->locale);
    }

    /**
     * Saying the whole profile is what provisioning does, and it clears what it is not told; a person
     * naming their language says one thing.
     */
    #[Test]
    public function whatThePersonSaidOfThemselvesIsLeftAlone(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = self::user($users);

        // When
        new LanguageRecording($users, new MockClock(Fixtures::now()))->record($user, 'fr');

        // Then
        $stored = $users->find($user->id)?->profile;
        static::assertSame('Alice Lovelace', $stored?->name);
        static::assertSame('Europe/London', $stored->zoneinfo);
    }

    #[Test]
    public function theAccountSaysItWasUpdated(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = self::user($users);
        $later = Fixtures::now()->modify('+1 hour');

        // When
        new LanguageRecording($users, new MockClock($later))->record($user, 'fr');

        // Then
        static::assertEquals($later, $users->find($user->id)?->updatedAt);
    }

    /**
     * Decision 0002: a language the source of the person holds is the provider's to write, so the account
     * is left as it was; the cookie of the browser keeps the choice.
     */
    #[Test]
    public function aLanguageTheSourceOfThePersonHoldsIsNotWritten(): void
    {
        // Given
        $users = new InMemoryUserRepository();
        $user = User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice',
            Fixtures::now(),
            source: UserSource::upstream('https://idp.acme.example/saml', ['locale']),
        );
        $user->updateProfile(new Profile(locale: 'en-GB'), Fixtures::now());
        $users->save($user);

        // When
        new LanguageRecording($users, new MockClock(Fixtures::now()->modify('+1 hour')))->record($user, 'fr');

        // Then
        static::assertSame('en-GB', $users->find($user->id)?->profile->locale);
        static::assertEquals(Fixtures::now(), $user->updatedAt);
    }

    private static function user(InMemoryUserRepository $users): User
    {
        $user = Fixtures::user();
        $user->updateProfile(new Profile(name: 'Alice Lovelace', zoneinfo: 'Europe/London', locale: 'en-GB'), Fixtures::now());
        $users->save($user);

        return $user;
    }
}
