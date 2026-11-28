<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Messenger;

use App\Message\SendLogoutToken;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\Subject;
use Closure;
use const E_DEPRECATED;
use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

final class CommandBusTest extends DatabaseTestCase
{
    public static function setUpBeforeClass(): void
    {
        self::bootKernel();
        self::ensureKernelShutdown();
    }

    #[Test]
    #[RunInSeparateProcess]
    public function theFirstMessageAProcessPutsOnTheBusRaisesNoDeprecation(): void
    {
        // Given
        $bus = self::service('command.bus', MessageBusInterface::class);
        $message = new SendLogoutToken(
            self::tenant(),
            'oidc-demo',
            'https://demo.test/backchannel-logout',
            'a-logout-token',
            Uuid::fromString('0192f0a4-8e1b-7c3d-9a2b-4c5d6e7f8091'),
            new Subject('alice-subject'),
            self::context(),
            new ThePerson(),
        );

        // When
        $deprecations = self::deprecationsRaisedWhile(static fn (): object => $bus->dispatch($message));

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * Includes the deprecations "@" silences: Symfony raises its own that way (trigger_deprecation()).
     *
     * @param Closure(): mixed $call
     *
     * @return list<string>
     */
    private static function deprecationsRaisedWhile(Closure $call): array
    {
        $deprecations = [];
        set_error_handler(static function (int $level, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);
        try {
            $call();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
