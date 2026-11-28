<?php

declare(strict_types=1);

namespace Beffroi\Core\Application\Author;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\AuthorKindInterface;
use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\AuthorReaderInterface;
use function sprintf;

/**
 * The kinds of author the wiring holds, each reading back the documents its authors wrote.
 */
final readonly class Authors implements AuthorReaderInterface
{
    /**
     * @var array<string, AuthorKindInterface>
     */
    private array $kinds;

    /**
     * @param iterable<AuthorKindInterface> $kinds
     *
     * @throws InvalidArgumentException when two kinds give themselves one name
     */
    public function __construct(iterable $kinds)
    {
        $wired = [];
        foreach ($kinds as $kind) {
            if (isset($wired[$kind->kind()])) {
                throw new InvalidArgumentException(sprintf('Two kinds of author give themselves the name "%s".', $kind->kind()));
            }
            $wired[$kind->kind()] = $kind;
        }
        $this->kinds = $wired;
    }

    public function fromDocument(array $document): AuthorInterface
    {
        $read = new Document($document);
        $named = $read->nullableString(AuthorInterface::MEMBER);
        $kind = $this->kinds[$named ?? ''] ?? throw new InvalidArgumentException(sprintf('"%s" is no kind of author this provider writes.', $named ?? ''));
        $author = $kind->fromDocument($read);
        if ($author->kind() !== $named) {
            throw new InvalidArgumentException(sprintf('The kind "%s" read back an author of the kind "%s".', $named, $author->kind()));
        }

        return $author;
    }
}
