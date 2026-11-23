<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Chain;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Domain\Chain\Checkpoint;
use Beffroi\Core\Domain\Chain\Link;
use Beffroi\Core\Exception\InvalidArgumentException;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0060
 */
final class CheckpointTest extends TestCase
{
    #[Test]
    public function aCheckpointReadsBackAsItWasWritten(): void
    {
        // Given
        $checkpoint = self::checkpoint();

        // When
        $read = Checkpoint::fromDocument(new Document($checkpoint->toDocument()));

        // Then
        static::assertEquals($checkpoint, $read);
    }

    #[Test]
    public function aChainIsWalkedNoFurtherThanItsHead(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A chain is walked no further than its head.');

        // When
        new Checkpoint(
            Uuid::v7(),
            'journal',
            new Link(3, str_repeat('a', 64)),
            new Link(1, str_repeat('b', 64)),
            new Link(4, str_repeat('a', 64)),
            new DateTimeImmutable('@1789000000'),
            new DateTimeImmutable('@1789000000'),
        );
    }

    #[Test]
    public function aChainKeepsNothingPastItsHead(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A chain keeps nothing past its head.');

        // When
        new Checkpoint(
            Uuid::v7(),
            'journal',
            new Link(3, str_repeat('a', 64)),
            new Link(4, str_repeat('b', 64)),
            new Link(3, str_repeat('a', 64)),
            new DateTimeImmutable('@1789000000'),
            new DateTimeImmutable('@1789000000'),
        );
    }

    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideIncompleteDocuments')]
    public function aDocumentThatDoesNotSayEverythingIsRefused(array $members): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        Checkpoint::fromDocument(new Document($members));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideIncompleteDocuments(): iterable
    {
        $document = self::checkpoint()->toDocument();
        foreach (['tenant', 'chain', 'head', 'kept_after', 'walked', 'iat'] as $member) {
            $without = $document;
            unset($without[$member]);

            yield 'no ' . $member => [$without];
        }

        yield 'a tenant that is no identifier' => [['tenant' => 'acme'] + $document];
        yield 'a head with no hash' => [['head' => ['position' => 2]] + $document];
        yield 'a moment as a string' => [['iat' => '1789000000'] + $document];
        yield 'a walk with no moment' => [['walked' => ['position' => 10, 'hash' => str_repeat('c', 64)]] + $document];
    }

    private static function checkpoint(): Checkpoint
    {
        return new Checkpoint(
            Uuid::fromString('019a8a3e-2a4b-7c3d-8e5f-6a7b8c9d0e1f'),
            'journal',
            new Link(12, str_repeat('a', 64)),
            new Link(3, str_repeat('b', 64)),
            new Link(10, str_repeat('c', 64)),
            new DateTimeImmutable('@1788990000'),
            new DateTimeImmutable('@1789000000'),
        );
    }
}
