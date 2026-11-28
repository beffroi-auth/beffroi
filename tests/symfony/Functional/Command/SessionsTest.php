<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserRevokeSessionCommand;
use App\Tests\Symfony\Functional\Controller\TokensOfASession;
use function array_map;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Oidc\Domain\Event\SessionTokensRevoked;
use PHPUnit\Framework\Attributes\Test;
use function str_starts_with;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Architecture §5.5
 */
final class SessionsTest extends ConsoleTestCase
{
    use TokensOfASession;

    #[Test]
    public function theSessionsOpenInTheNameOfTheUserAreListed(): void
    {
        // Given
        $session = self::session(self::user('alice'), self::currentSecond());

        // When
        $tester = self::list('alice');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString($session->id->toString(), $tester->getDisplay());
    }

    #[Test]
    public function aUserWithNoSessionIsSaidToHaveNone(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::list('alice');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('No session is open', $tester->getDisplay());
    }

    #[Test]
    public function theSessionIsEndedByItsIdentifier(): void
    {
        // Given
        $session = self::session(self::user('alice'), self::currentSecond());

        // When
        $tester = self::end('alice', $session->id->toString());

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertTrue(self::sessionAgain($session)->hasEnded());
        static::assertSame(SessionEnd::Administrator, self::sessionAgain($session)->endedBy);
    }

    /**
     * Decision 0022, Architecture §5.5
     */
    #[Test]
    public function theTokensASessionEndedAtTheConsoleLostAreAnActFromTheConsole(): void
    {
        // Given
        $session = self::session(self::user('alice'), self::currentSecond());
        self::tokensIssuedIn($session);

        // When
        self::end('alice', $session->id->toString());

        // Then
        static::assertSame([['oidc-demo', 1, 1, null, true]], array_map(
            static fn (SessionTokensRevoked $act): array => [
                $act->clientId,
                $act->refreshTokens,
                $act->accessTokens,
                $act->author(),
                str_starts_with((string) $act->context->userAgent, 'beffroi-console/' . UserRevokeSessionCommand::NAME . ' '),
            ],
            self::events(SessionTokensRevoked::class),
        ));
    }

    #[Test]
    public function aSessionThatEndedAlreadyIsSaidToHave(): void
    {
        // Given
        $session = self::session(self::user('alice'), self::currentSecond());
        self::end('alice', $session->id->toString());

        // When
        $tester = self::end('alice', $session->id->toString());

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('ended on', $tester->getDisplay());
    }

    #[Test]
    public function aSessionOfSomebodyElseIsNotTheirs(): void
    {
        // Given
        self::user('alice');
        $theirs = self::session(self::user('bob', 'bob-subject'), self::currentSecond());

        // When
        $tester = self::end('alice', $theirs->id->toString());

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertFalse(self::sessionAgain($theirs)->hasEnded());
    }

    #[Test]
    public function somethingThatIsNotAnIdentifierIsRefused(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::end('alice', 'not-an-identifier');

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
    }

    private static function list(string $username): CommandTester
    {
        return self::console('beffroi:user:sessions', ['username' => $username]);
    }

    private static function end(string $username, string $id): CommandTester
    {
        return self::console('beffroi:user:revoke-session', [
            'username' => $username,
            'id' => $id,
        ]);
    }
}
