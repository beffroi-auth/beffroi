<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Chain;

use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Tests\Fixture\ChainOfWrittenRows;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SignedChain;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0060
 */
final class ChainVerificationTest extends TestCase
{
    private SignedChain $chain;

    protected function setUp(): void
    {
        $this->chain = new SignedChain();
    }

    #[Test]
    public function aChainWithNoRowHoldsTogether(): void
    {
        // When
        $verified = $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertSame([0, null], [$verified->end->position, $verified->signed]);
    }

    #[Test]
    public function rowsWrittenOneAfterAnotherFollowEachOther(): void
    {
        // Given
        $this->writeThree();

        // When
        $verified = $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertTrue($verified->end->equals($this->chain->rows->head));
    }

    #[Test]
    public function aRowChangedInTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        $this->writeThree();
        $this->chain->rows->rewrite(2, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The row at position 2 of the chain "journal" is not the one written there.');

        // When
        $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function aRowRemovedFromTheDatabaseIsNamedByItsPosition(): void
    {
        // Given
        $this->writeThree();
        $this->chain->rows->remove(2);

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The row at position 2 of the chain "journal" is missing.');

        // When
        $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function aRowAddedToTheDatabaseOutsideTheChainIsCounted(): void
    {
        // Given
        $this->writeThree();
        $this->chain->rows->insertWithoutALink();

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('1 row(s) of the chain "journal" are not in it.');

        // When
        $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function aSignedRowRewrittenWithEveryLinkComputedAgainIsSeenAtTheSignedPosition(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->rewriteAndRelink(2, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The rows up to position 3 of the chain "journal" are not the ones signed.');

        // When
        $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function theWalkSinceTheSignatureSeesTheSignedRowRewrittenWithItsLinks(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->rewriteAndRelink(2, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The rows up to position 3 of the chain "journal" are not the ones signed.');

        // When
        $this->chain->verification()->sinceTheSignature($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function theWalkSinceTheSignatureSeesTheFirstRowKeptRemoved(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->remove(1);

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The row at position 1 of the chain "journal" is missing.');

        // When
        $this->chain->verification()->sinceTheSignature($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function theWalkSinceTheSignatureSeesARowWrittenSinceChanged(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->write();
        $this->chain->rows->rewrite(4, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The row at position 4 of the chain "journal" is not the one written there.');

        // When
        $this->chain->verification()->sinceTheSignature($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function theWalkSinceTheSignatureLeavesTheRowsBetweenToTheWholeWalk(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->rewrite(2, ChainOfWrittenRows::row(Fixtures::now(), 'user.signed_out'));

        // When
        $verified = $this->chain->verification()->sinceTheSignature($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertSame(3, $verified->end->position);
    }

    #[Test]
    public function theLastSignedRowRemovedIsSeen(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->remove(3);

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The rows from position 3 to position 3 of the chain "journal" are missing.');

        // When
        $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function aSignatureThatDoesNotVerifyIsSeen(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->kept->putBack('eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl');

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The signature of the chain "journal" does not verify: The token does not name its key.');

        // When
        $this->chain->verification()->whole($this->chain->tenant, $this->chain->chain);
    }

    #[Test]
    public function theRowsWrittenSinceTheLastSignatureAreCounted(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $this->chain->rows->write();

        // When
        $verified = $this->chain->verification()->sinceTheSignature($this->chain->tenant, $this->chain->chain);

        // Then
        static::assertSame(1, $verified->unsigned());
    }

    #[Test]
    public function aChainCutShortWithAnOlderSignaturePutBackIsSeenAgainstACopyKeptOutside(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $older = $this->chain->kept->kept[0];
        $this->chain->rows->write();
        $this->chain->sign();
        $copy = $this->chain->kept->kept[1];
        $this->chain->rows->cutShortAt(3);
        $this->chain->kept->putBack($older);

        // Then
        $this->expectException(BrokenChainException::class);
        $this->expectExceptionMessageIs('The chain "journal" ends at position 3, and a copy of its head signed at 2026-09-15T10:00:00+00:00 holds position 4.');

        // When
        $this->chain->verification()->wholeAgainst($this->chain->tenant, $this->chain->chain, $copy);
    }

    #[Test]
    public function aCopyTheChainStillHoldsIsHeld(): void
    {
        // Given
        $this->writeThree();
        $this->chain->sign();
        $copy = $this->chain->kept->kept[0];
        $this->chain->rows->write();
        $this->chain->sign();

        // When
        $verified = $this->chain->verification()->wholeAgainst($this->chain->tenant, $this->chain->chain, $copy);

        // Then
        static::assertSame(4, $verified->end->position);
    }

    private function writeThree(): void
    {
        $this->chain->rows->write();
        $this->chain->rows->write();
        $this->chain->rows->write();
    }
}
