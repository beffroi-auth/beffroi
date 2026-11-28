<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\AuthorReaderInterface;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use JsonException;
use LogicException;
use function rtrim;
use function str_starts_with;

/**
 * The document of an author, as text. A row written before authors had kinds holds an administrator by their bare
 * subject, which never begins with a brace (Version20261128141800), and anybody else by NULL: it is never rewritten,
 * its record being a chain whose head the provider signed (decision 0060).
 */
abstract class WrittenAuthorType extends Type implements NeedsAuthorReaderInterface
{
    private const string DOCUMENT = '{';

    private static ?AuthorReaderInterface $authors = null;

    public static function resolveWith(AuthorReaderInterface $authors): void
    {
        self::$authors = $authors;
    }

    /**
     * What a row holds of the author, the same bytes whichever record holds it.
     *
     * @throws JsonException
     */
    public static function written(AuthorInterface $author): string
    {
        return self::encoded($author->toDocument());
    }

    /**
     * A pattern of LIKE that every document of an author of the kind matches and no other: the kind is the first member
     * of the document, and the names of the kinds are lowercase letters, which a pattern reads as themselves.
     *
     * @param non-empty-string $kind
     *
     * @throws JsonException
     */
    public static function documentsOfKind(string $kind): string
    {
        return rtrim(self::encoded([AuthorInterface::MEMBER => $kind]), '}') . '%';
    }

    /**
     * A pattern of LIKE that every document of an author matches, and no bare subject a row written before them holds.
     */
    public static function documents(): string
    {
        return self::DOCUMENT . '%';
    }

    /**
     * What a row written before acts named the kind of their author stands for when it names nobody.
     */
    abstract protected function unwritten(): ?AuthorInterface;

    abstract protected function name(): string;

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! $value instanceof AuthorInterface) {
            throw InvalidType::new($value, $this->name(), ['null', AuthorInterface::class]);
        }

        try {
            return self::written($value);
        } catch (JsonException $exception) {
            throw ValueNotConvertible::new($value, $this->name(), $exception->getMessage(), $exception);
        }
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?AuthorInterface
    {
        if ($value === null) {
            return $this->unwritten();
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, $this->name(), ['null', 'string']);
        }

        try {
            return str_starts_with($value, self::DOCUMENT) ? self::read($value) : new AnAdministrator(new Subject($value));
        } catch (InvalidArgumentException|JsonException $exception) {
            throw ValueNotConvertible::new($value, $this->name(), $exception->getMessage(), $exception);
        }
    }

    /**
     * @throws InvalidArgumentException
     * @throws JsonException
     */
    private static function read(string $value): AuthorInterface
    {
        $authors = self::$authors ?? throw new LogicException('The kinds of author have not been handed to the DBAL type; the kernel does it when it boots.');
        $document = json_decode($value, true, 2, JSON_THROW_ON_ERROR);
        if (! is_array($document)) {
            throw new InvalidArgumentException('The author of an act is written as a JSON object.');
        }

        return $authors->fromDocument($document);
    }

    /**
     * @param array<string, string> $document
     *
     * @throws JsonException
     */
    private static function encoded(array $document): string
    {
        return json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
