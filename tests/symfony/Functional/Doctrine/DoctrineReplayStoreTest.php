<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Bundle\Doctrine\Repository\DoctrineReplayStore;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;

/**
 * beffroi/saml, spec/saml.md S-23, model.md M-11: the store of the assertions and of the logout messages the model accepted forgets a message
 * once the window in which the model would accept it again has closed, the rows past it deleted before each insertion,
 * and never one whose window is still open.
 */
final class DoctrineReplayStoreTest extends DatabaseTestCase
{
    private const string ISSUER = 'https://sp.example.org/saml';

    private MockClock $clock;

    protected function setUp(): void
    {
        parent::setUp();
        $this->clock = new MockClock(self::now());
    }

    /**
     * S-23, M-11: a message whose window has closed is forgotten at the next insertion, so that the same message is
     * remembered again as new.
     */
    #[Test]
    public function aMessageWhoseWindowHasClosedIsRememberedAgain(): void
    {
        // Given
        $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', self::endOfWindow());
        $this->clock->modify('+481 seconds');

        // When
        $remembered = $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', $this->clock->now()->modify('+480 seconds'));

        // Then
        static::assertTrue($remembered);
    }

    /**
     * S-23: the deletion before an insertion leaves the row of a message whose window is still open, so that the same
     * message, a second before its window closes, is still refused.
     */
    #[Test]
    public function aMessageWhoseWindowIsStillOpenSurvivesTheDeletion(): void
    {
        // Given
        $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', self::endOfWindow());
        $this->clock->modify('+479 seconds');

        // When
        $remembered = $this->store()->remember(self::tenant(), self::ISSUER, '_request-1', self::endOfWindow());

        // Then
        static::assertFalse($remembered);
    }

    /**
     * The end of the window of a message received at the instant of the test, the 480 seconds of S-23 at most.
     */
    private static function endOfWindow(): DateTimeImmutable
    {
        return self::now()->modify('+480 seconds');
    }

    private function store(): DoctrineReplayStore
    {
        return new DoctrineReplayStore(self::managers(), $this->clock);
    }
}
