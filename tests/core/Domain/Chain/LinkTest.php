<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Chain;

use Beffroi\Core\Domain\Chain\Link;
use Beffroi\Core\Domain\Chain\WrittenRow;
use Beffroi\Core\Exception\InvalidArgumentException;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Decision 0060
 */
final class LinkTest extends TestCase
{
    private const string ID = '019a8a3e-2a4b-7c3d-8e5f-0a1b2c3d4e5f';

    private const string TENANT = '019a8a3e-2a4b-7c3d-8e5f-6a7b8c9d0e1f';

    #[Test]
    public function theChainStartsAtPositionZeroWithAHashOfZeros(): void
    {
        // When
        $first = Link::beforeTheFirst();

        // Then
        static::assertSame([0, str_repeat('0', 64)], [$first->position, $first->hash]);
    }

    #[Test]
    public function anActTakesThePositionAfterTheLinkBeforeIt(): void
    {
        // When / Then
        static::assertSame(8, new Link(7, str_repeat('a', 64))->then(self::act())->position);
    }

    #[Test]
    public function theSameActAfterTheSameLinkGivesTheSameLink(): void
    {
        // When / Then
        static::assertTrue(Link::beforeTheFirst()->then(self::act())->equals(Link::beforeTheFirst()->then(self::act())));
    }

    #[Test]
    #[DataProvider('provideChangedActs')]
    public function aChangeOfAnyFieldOfTheRowChangesTheLink(WrittenRow $changed): void
    {
        // When / Then
        static::assertNotSame(Link::beforeTheFirst()->then(self::act())->hash, Link::beforeTheFirst()->then($changed)->hash);
    }

    /**
     * @return iterable<string, array{WrittenRow}>
     */
    public static function provideChangedActs(): iterable
    {
        yield 'the identifier' => [self::act(id: '019a8a3e-2a4b-7c3d-8e5f-0a1b2c3d4e60')];
        yield 'the tenant' => [self::act(tenant: '019a8a3e-2a4b-7c3d-8e5f-6a7b8c9d0e20')];
        yield 'the name' => [self::act(act: 'user.signed_out')];
        yield 'the moment' => [self::act(occurredAt: new DateTimeImmutable('2026-09-15 10:00:01'))];
        yield 'the person' => [self::act(subject: 'bob-subject')];
        yield 'no person' => [self::act(subject: null)];
        yield 'an empty person' => [self::act(subject: '')];
        yield 'the client' => [self::act(client: 'oidc-demo')];
        yield 'the author' => [self::act(author: 'carol-subject')];
        yield 'one byte of the seal' => [self::act(sealedContext: 'sealed provenancE')];
        yield 'a byte moved from the person to the client' => [self::act(subject: 'alice-subjec', client: 't')];
        yield 'a column more' => [new WrittenRow(self::ID, self::TENANT, new DateTimeImmutable('2026-09-15 10:00:00'), [
            'user.authenticated',
            'alice-subject',
            null,
            null,
            'sealed provenance',
            null,
        ])];
    }

    #[Test]
    public function theSameActAfterAnotherLinkGivesAnotherLink(): void
    {
        // When / Then
        static::assertNotSame(Link::beforeTheFirst()->then(self::act())->hash, new Link(0, str_repeat('1', 64))->then(self::act())->hash);
    }

    #[Test]
    #[DataProvider('provideNoHashes')]
    public function aHashThatIsNoSha256InLowercaseHexadecimalIsRefused(string $hash): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A link of the chain is a SHA-256 in lowercase hexadecimal.');

        // When
        new Link(1, $hash);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNoHashes(): iterable
    {
        yield 'empty' => [''];
        yield 'one character short' => [str_repeat('a', 63)];
        yield 'one character long' => [str_repeat('a', 65)];
        yield 'uppercase' => [str_repeat('A', 64)];
        yield 'not hexadecimal' => [str_repeat('g', 64)];
        yield 'a trailing line feed' => [str_repeat('a', 64) . "\n"];
    }

    #[Test]
    public function aNegativePositionIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A position of the chain is zero or more, "-1" given.');

        // When
        new Link(-1, str_repeat('0', 64));
    }

    private static function act(
        string $id = self::ID,
        string $tenant = self::TENANT,
        string $act = 'user.authenticated',
        ?DateTimeImmutable $occurredAt = null,
        ?string $subject = 'alice-subject',
        ?string $client = null,
        ?string $author = null,
        string $sealedContext = 'sealed provenance',
    ): WrittenRow {
        return new WrittenRow($id, $tenant, $occurredAt ?? new DateTimeImmutable('2026-09-15 10:00:00'), [$act, $subject, $client, $author, $sealedContext]);
    }
}
