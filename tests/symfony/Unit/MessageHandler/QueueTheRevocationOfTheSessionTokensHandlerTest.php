<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\MessageHandler;

use App\Message\RevokeTheTokensOfTheSession;
use App\MessageHandler\QueueTheRevocationOfTheSessionTokensHandler;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DispatchAfterCurrentBusStamp;

/**
 * Architecture §4.9, §5.6
 */
final class QueueTheRevocationOfTheSessionTokensHandlerTest extends TestCase
{
    #[Test]
    public function theCommandCarriesTheEndOfTheSession(): void
    {
        // Given
        $bus = self::bus();
        $event = self::endedByAnAdministrator();

        // When
        (new QueueTheRevocationOfTheSessionTokensHandler($bus))($event);

        // Then
        $command = $bus->envelopes[0]->getMessage();
        static::assertInstanceOf(RevokeTheTokensOfTheSession::class, $command);
        static::assertEquals(
            [$event->tenant, $event->session->id, $event->occurredAt, $event->subject(), $event->context, $event->administrator],
            [$command->tenant, $command->sessionId, $command->endedAt, $command->subject, $command->context, $command->administrator],
        );
    }

    #[Test]
    public function theCommandLeavesOnceTheEndIsHandledWhole(): void
    {
        // Given
        $bus = self::bus();

        // When
        (new QueueTheRevocationOfTheSessionTokensHandler($bus))(self::endedByAnAdministrator());

        // Then
        static::assertNotNull($bus->envelopes[0]->last(DispatchAfterCurrentBusStamp::class));
    }

    private static function endedByAnAdministrator(): AuthenticationSessionEnded
    {
        $session = Fixtures::session();
        $session->end(SessionEnd::Administrator, Fixtures::now());

        return new AuthenticationSessionEnded($session, Fixtures::now(), Fixtures::context(), new Subject('administrator-subject'));
    }

    /**
     * @return MessageBusInterface&object{envelopes: list<Envelope>}
     */
    private static function bus(): MessageBusInterface
    {
        return new class() implements MessageBusInterface {
            /**
             * @var list<Envelope>
             */
            public array $envelopes = [];

            public function dispatch(object $message, array $stamps = []): Envelope
            {
                $this->envelopes[] = $envelope = Envelope::wrap($message, $stamps);

                return $envelope;
            }
        };
    }
}
