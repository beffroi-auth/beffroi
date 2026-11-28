<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\MessageHandler;

use App\Message\RevokeTheTokensOfTheSession;
use App\MessageHandler\QueueTheRevocationOfTheSessionTokensHandler;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\HandlerFailedException;
use Symfony\Component\Messenger\Handler\HandlerDescriptor;
use Symfony\Component\Messenger\Handler\HandlersLocator;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Messenger\Middleware\DispatchAfterCurrentBusMiddleware;
use Symfony\Component\Messenger\Middleware\HandleMessageMiddleware;

/**
 * Architecture §4.9, §5.6
 */
final class QueueTheRevocationOfTheSessionTokensHandlerTest extends TestCase
{
    private int $endsWritten = 0;

    private int $commandsHandled = 0;

    private int $failuresLeft = 2;

    #[Test]
    public function theCommandCarriesTheEndOfTheSession(): void
    {
        // Given
        $commands = [];
        $handler =
            new QueueTheRevocationOfTheSessionTokensHandler(self::busOf(RevokeTheTokensOfTheSession::class, static function (RevokeTheTokensOfTheSession $command) use (
                &$commands,
            ): void {
                $commands[] = $command;
            }));
        $event = self::endedByAnAdministrator();

        // When
        $handler($event);

        // Then
        $command = $commands[0] ?? static::fail('No command was sent.');
        static::assertEquals(
            [$event->tenant, $event->session->id, $event->occurredAt, $event->subject(), $event->context, $event->author()],
            [$command->tenant, $command->sessionId, $command->endedAt, $command->subject, $command->context, $command->author],
        );
    }

    /**
     * Decision 0060: a handler of the end that fails has the end retried, and the act of the end is written once.
     */
    #[Test]
    public function aHandlerOfTheEndThatFailsLeavesTheEndWrittenOnce(): void
    {
        // When
        $this->endHandledUntilItsHandlersSucceed();

        // Then
        static::assertSame(1, $this->endsWritten);
    }

    #[Test]
    public function aHandlerOfTheEndThatFailsLeavesTheCommandSentOnce(): void
    {
        // When
        $this->endHandledUntilItsHandlersSucceed();

        // Then
        static::assertSame(1, $this->commandsHandled);
    }

    /**
     * What a worker does with the end of a session while the back-channel logout fails twice, its KMS out of reach: the
     * envelope the failure carries is the one retried, with the stamps of the handlers that succeeded, as the
     * transport's retry of Messenger hands it back.
     */
    private function endHandledUntilItsHandlersSucceed(): void
    {
        $dispatchAfter = new DispatchAfterCurrentBusMiddleware();
        $commandBus = new MessageBus([
            $dispatchAfter,
            new HandleMessageMiddleware(new HandlersLocator([
                RevokeTheTokensOfTheSession::class => [new HandlerDescriptor(function (): void {
                    ++$this->commandsHandled;
                }, ['alias' => 'revoke_the_tokens_of_the_session'])],
            ])),
        ]);
        $eventBus = new MessageBus([
            $dispatchAfter,
            new HandleMessageMiddleware(new HandlersLocator([
                AuthenticationSessionEnded::class => [
                    new HandlerDescriptor(function (): void {
                        ++$this->endsWritten;
                    }, ['alias' => 'write_the_act_down']),
                    new HandlerDescriptor(function (): void {
                        if ($this->failuresLeft-- > 0) {
                            throw new RuntimeException('The KMS did not answer.');
                        }
                    }, ['alias' => 'back_channel_logout']),
                    new HandlerDescriptor(new QueueTheRevocationOfTheSessionTokensHandler($commandBus), ['alias' => 'queue_the_revocation']),
                ],
            ])),
        ]);
        $envelope = Envelope::wrap(self::endedByAnAdministrator());
        for ($attempt = 1; $attempt <= 3; ++$attempt) {
            try {
                $eventBus->dispatch($envelope);

                return;
            } catch (HandlerFailedException $failure) {
                $envelope = $failure->getEnvelope();
            }
        }
        static::fail('The end of the session was never handled.');
    }

    private static function endedByAnAdministrator(): AuthenticationSessionEnded
    {
        $session = Fixtures::session();
        $session->end(SessionEnd::Administrator, Fixtures::now());

        return new AuthenticationSessionEnded($session, Fixtures::now(), Fixtures::context(), new AnAdministrator(new Subject('administrator-subject')));
    }

    /**
     * @param class-string $message
     */
    private static function busOf(string $message, callable $handler): MessageBus
    {
        return new MessageBus([new HandleMessageMiddleware(new HandlersLocator([
            $message => [new HandlerDescriptor($handler)],
        ]))]);
    }
}
