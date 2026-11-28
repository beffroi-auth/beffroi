<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Oidc\Port\AnnouncedSessionEndsInterface;
use PHPUnit\Framework\Attributes\Test;

/**
 * Architecture §4.9
 */
final class DoctrineAnnouncedSessionEndsTest extends DatabaseTestCase
{
    #[Test]
    public function theFirstAnnouncementOfTheEndOfASessionIsRecorded(): void
    {
        // Given
        $session = self::session(self::user());

        // When / Then
        static::assertTrue(self::announced()->announceOnce($session->tenant, $session->id));
    }

    #[Test]
    public function theEndOfASessionIsAnnouncedOnce(): void
    {
        // Given
        $session = self::session(self::user());
        self::announced()->announceOnce($session->tenant, $session->id);

        // When / Then
        static::assertFalse(self::announced()->announceOnce($session->tenant, $session->id));
    }

    #[Test]
    public function theEndOfAnotherSessionIsAnnouncedOnItsOwn(): void
    {
        // Given
        $user = self::user();
        self::announced()->announceOnce($user->tenant, self::session($user)->id);

        // When / Then
        static::assertTrue(self::announced()->announceOnce($user->tenant, self::session($user, self::now()->modify('+1 minute'))->id));
    }

    private static function announced(): AnnouncedSessionEndsInterface
    {
        return self::service('test.beffroi.announced_session_ends', AnnouncedSessionEndsInterface::class);
    }
}
