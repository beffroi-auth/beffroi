<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Chain;

use Beffroi\Core\Application\Chain\ChainCheckpoints;
use Beffroi\Core\Domain\Chain\Link;
use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenRows;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedChain;
use function base64_decode;
use function explode;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtr;

/**
 * Decision 0060, RFC 8725 §3.11
 */
final class ChainSignatureTest extends TestCase
{
    private SignedChain $chain;

    protected function setUp(): void
    {
        $this->chain = new SignedChain();
        $this->chain->rows->write();
        $this->chain->rows->write();
    }

    #[Test]
    public function theSignatureNamesTheHeadOfTheChain(): void
    {
        // When
        $checkpoint = $this->chain->signature()->sign($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertTrue($checkpoint->head->equals($this->chain->rows->head));
    }

    #[Test]
    public function theSignatureIsTakenUnderTheLockOfTheHead(): void
    {
        // When
        $this->chain->sign();

        // Then
        static::assertSame(1, $this->chain->rows->locks);
    }

    #[Test]
    public function theSignatureIsAJwsOfTheTypeOfACheckpointOfAChain(): void
    {
        // When
        $this->chain->sign();

        // Then
        $header = json_decode((string) base64_decode(strtr(explode('.', $this->chain->kept->kept[0])[0], '-_', '+/'), true), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($header);
        static::assertSame(ChainCheckpoints::TYPE, $header['typ'] ?? null);
    }

    #[Test]
    public function eachSignatureLeavesACopyOutsideTheInstance(): void
    {
        // When
        $this->chain->sign();

        // Then
        static::assertSame(2, ($this->chain->kept->copies[0] ?? null)?->head->position);
    }

    #[Test]
    public function aFirstSignatureKeepsTheChainFromItsFirstRow(): void
    {
        // When
        $checkpoint = $this->chain->signature()->sign($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertTrue($checkpoint->keptAfter->equals(Link::beforeTheFirst()));
    }

    #[Test]
    public function aFirstSignatureWalksTheWholeChain(): void
    {
        // When
        $checkpoint = $this->chain->signature()->sign($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertTrue($checkpoint->walked->equals($checkpoint->head));
    }

    #[Test]
    public function aLaterSignatureCarriesTheLastWholeWalk(): void
    {
        // Given
        $first = $this->chain->signature()->sign($this->chain->tenant, $this->chain->chain);
        $this->chain->rows->write();
        $this->chain->clock->modify('+5 minutes');

        // When
        $checkpoint = $this->chain->signature()->sign($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertEquals([$first->walked, $first->walkedAt], [$checkpoint->walked, $checkpoint->walkedAt]);
    }

    #[Test]
    public function aChainRewrittenBeforeTheLastSignatureIsNotSignedAgain(): void
    {
        // Given
        $this->chain->sign();
        $this->chain->rows->rewriteAndRelink(1, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));
        $this->chain->rows->write();

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The row at position 3 of the chain "journal" is not the one written there.');

        // When
        $this->chain->sign();
    }

    #[Test]
    public function aSignatureUnderAKeyRetiredAtOnceStillVerifies(): void
    {
        // Given
        $this->chain->sign();
        $this->chain->retireTheKeyThatSignedAtOnce();
        $this->chain->rows->write();

        // When
        $checkpoint = $this->chain->signature()->sign($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertSame(3, $checkpoint->head->position);
    }
}
