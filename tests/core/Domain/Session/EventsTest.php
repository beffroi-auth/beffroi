<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EventsTest extends TestCase
{
    /**
     * Architecture §3.5
     */
    #[Test]
    public function userAuthenticatedCarriesTheContextOfTheSession(): void
    {
        // Given
        $session = Fixtures::session();

        // When
        $event = new UserAuthenticated($session);

        // Then
        static::assertSame($session->establishedAt, $event->occurredAt);
        static::assertSame($session->tenant, $event->tenant);
        static::assertSame($session->createdFrom, $event->context);
    }

    #[Test]
    public function sessionEndedCarriesTheContextOfTheRequestThatEndedIt(): void
    {
        // Given
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+1 hour');
        $context = Fixtures::context($later, '198.51.100.7');
        $session->end(SessionEnd::RelyingParty, $later);

        // When
        $event = new AuthenticationSessionEnded($session, $later, $context, new ThePerson());

        // Then
        static::assertSame(SessionEnd::RelyingParty, $event->endedBy);
        static::assertSame($context, $event->context);
        static::assertSame($session->tenant, $event->tenant);
    }

    #[Test]
    public function sessionEndedRequiresAnEndedSession(): void
    {
        // Given
        $session = Fixtures::session();

        // Then
        $this->expectException(LogicException::class);

        // When
        new AuthenticationSessionEnded($session, Fixtures::now(), Fixtures::context(), new ThePerson());
    }
}
