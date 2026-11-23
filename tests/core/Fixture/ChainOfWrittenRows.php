<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_filter;
use function array_map;
use function array_slice;
use function array_values;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Chain\Link;
use Beffroi\Core\Domain\Chain\LinkedRow;
use Beffroi\Core\Domain\Chain\RelinkedChain;
use Beffroi\Core\Domain\Chain\WrittenRow;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\ChainOfRowsInterface;
use Beffroi\Core\Port\RelinkableChainsInterface;
use function count;
use DateTimeImmutable;
use function ksort;
use Symfony\Component\Uid\Uuid;

/**
 * The rows of one chain of one tenant, which a test can rewrite as whoever holds the database would.
 */
final class ChainOfWrittenRows implements ChainOfRowsInterface, RelinkableChainsInterface
{
    public private(set) Link $head;

    public private(set) int $locks = 0;

    /**
     * @var array<int, LinkedRow> by position
     */
    private array $links = [];

    /**
     * @var list<WrittenRow>
     */
    private array $unlinked = [];

    public function __construct()
    {
        $this->head = Link::beforeTheFirst();
    }

    public function write(?DateTimeImmutable $moment = null): Link
    {
        return $this->append(self::row($moment ?? Fixtures::now()));
    }

    public static function row(DateTimeImmutable $moment, string $what = 'user.authenticated'): WrittenRow
    {
        return new WrittenRow(Uuid::v7()->toRfc4122(), Uuid::v7()->toRfc4122(), $moment, [$what, 'alice-subject', null, null, 'sealed provenance']);
    }

    public function rewrite(int $position, WrittenRow $row): void
    {
        $linked = $this->links[$position];
        $this->links[$position] = new LinkedRow($row, $linked->position, $linked->previous, $linked->hash);
    }

    /**
     * Each link from that position on computed again, as whoever holds the database can.
     */
    public function rewriteAndRelink(int $position, WrittenRow $row): void
    {
        $this->rewrite($position, $row);
        $before = new Link($position - 1, $this->links[$position]->previous);
        ksort($this->links);
        foreach ($this->links as $at => $linked) {
            if ($at < $position) {
                continue;
            }
            $link = $before->then($linked->row);
            $this->links[$at] = new LinkedRow($linked->row, $at, $before->hash, $link->hash);
            $before = $link;
        }
        $this->head = $before;
    }

    /**
     * The last rows removed with their links, and the head put back, as whoever holds the database can.
     */
    public function cutShortAt(int $position): void
    {
        foreach ($this->links as $at => $linked) {
            if ($at > $position) {
                unset($this->links[$at]);
            }
        }
        $this->head = new Link($position, $this->links[$position]->hash);
    }

    public function remove(int $position): void
    {
        unset($this->links[$position]);
    }

    public function insertWithoutALink(): void
    {
        $this->unlinked[] = self::row(Fixtures::now());
    }

    public function lockedHead(Tenant $tenant, ChainInterface $chain): Link
    {
        ++$this->locks;

        return $this->head;
    }

    public function head(Tenant $tenant, ChainInterface $chain): Link
    {
        return $this->head;
    }

    public function linkedAfter(Tenant $tenant, ChainInterface $chain, int $position, int $howMany): array
    {
        ksort($this->links);

        return array_slice(array_values(array_filter($this->links, static fn (LinkedRow $linked): bool => $linked->position > $position)), 0, $howMany);
    }

    public function rowsOutsideTheChain(Tenant $tenant, ChainInterface $chain, int $keptAfter): int
    {
        return count($this->unlinked) + count(array_filter($this->links, static fn (LinkedRow $linked): bool => $linked->position <= $keptAfter));
    }

    public function forgetUpTo(Tenant $tenant, ChainInterface $chain, int $position): int
    {
        $before = count($this->links);
        $this->links = array_filter($this->links, static fn (LinkedRow $linked): bool => $linked->position > $position);

        return $before - count($this->links);
    }

    public function relink(Tenant $tenant, ChainInterface $chain): RelinkedChain
    {
        ksort($this->links);
        $rows = [...array_values(array_map(static fn (LinkedRow $linked): WrittenRow => $linked->row, $this->links)), ...$this->unlinked];
        $first = array_values($this->links)[0] ?? null;
        $start = $first?->before() ?? Link::beforeTheFirst();
        $this->links = [];
        $this->unlinked = [];
        $this->head = $start;
        foreach ($rows as $row) {
            $this->append($row);
        }

        return new RelinkedChain($start, $this->head);
    }

    private function append(WrittenRow $row): Link
    {
        $link = $this->head->then($row);
        $this->links[$link->position] = new LinkedRow($row, $link->position, $this->head->hash, $link->hash);
        $this->head = $link;

        return $link;
    }
}
