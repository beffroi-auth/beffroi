<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Message\RevokeTheTokensOfTheSession;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use App\Tests\Symfony\Functional\Controller\TokensOfASession;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * Architecture §4.9, §5.6
 */
final class TheTokensOfAnEndedSessionAreAnnouncedOnceTest extends BrowserTestCase
{
    use TokensOfASession;

    /**
     * Decision 0060: the end of a session run again, when a handler of it failed after it had sent a message, sends the
     * revocation a second time, which writes nothing more to the journal.
     */
    #[Test]
    public function theRevocationSentTwiceForOneEndWritesOneAct(): void
    {
        // Given
        $session = self::session(self::user('alice'), self::currentSecond()->modify('-1 hour'));
        self::tokensIssuedIn($session);
        $command = new RevokeTheTokensOfTheSession(
            $session->tenant,
            $session->id,
            self::currentSecond(),
            $session->user->subject,
            self::context(),
            new ThePerson(),
        );
        $commands = self::service('test.beffroi.command_bus', MessageBusInterface::class);
        $commands->dispatch($command);

        // When
        $commands->dispatch($command);

        // Then
        self::reload();
        static::assertCount(1, self::entityManager()->getRepository(JournalEntry::class)->findBy(['act' => SessionTokensRevoked::NAME]));
    }
}
