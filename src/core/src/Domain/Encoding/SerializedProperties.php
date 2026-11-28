<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Encoding;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\InvalidArgumentException;
use function array_is_list;
use function get_debug_type;
use function is_array;
use function is_string;
use function sprintf;

/**
 * The properties of an object a queue held, as `unserialize()` hands them to `__unserialize()`, read one by one: a
 * property of another type is refused, never coerced.
 */
final readonly class SerializedProperties
{
    /**
     * @param array<array-key, mixed> $properties
     */
    public function __construct(
        private array $properties,
    ) {
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @throws InvalidArgumentException
     *
     * @return T
     */
    public function object(string $name, string $class): object
    {
        $value = $this->properties[$name] ?? null;
        if (! $value instanceof $class) {
            throw new InvalidArgumentException(sprintf('The property "%s" of a body read back is a %s, got %s.', $name, $class, get_debug_type($value)));
        }

        return $value;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @throws InvalidArgumentException
     *
     * @return T|null null when the body holds no such property, as one the version before wrote
     */
    public function nullableObject(string $name, string $class): ?object
    {
        return isset($this->properties[$name]) ? $this->object($name, $class) : null;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function string(string $name): string
    {
        $value = $this->properties[$name] ?? null;
        if (! is_string($value)) {
            throw new InvalidArgumentException(sprintf('The property "%s" of a body read back is a string, got %s.', $name, get_debug_type($value)));
        }

        return $value;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return list<string>
     */
    public function strings(string $name): array
    {
        $strings = [];
        foreach ($this->list($name) as $value) {
            $strings[] = is_string($value)
                ? $value
                : throw new InvalidArgumentException(sprintf('The property "%s" of a body read back is a list of strings.', $name));
        }

        return $strings;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @throws InvalidArgumentException
     *
     * @return list<T>
     */
    public function objects(string $name, string $class): array
    {
        $objects = [];
        foreach ($this->list($name) as $value) {
            $objects[] = $value instanceof $class
                ? $value
                : throw new InvalidArgumentException(sprintf('The property "%s" of a body read back is a list of %s.', $name, $class));
        }

        return $objects;
    }

    /**
     * The author of the act, or, for a body written before acts named the kind of their author, the administrator it
     * named; one that named nobody came from the host when its provenance holds no address, the console and the schedule
     * giving none, and from the author given otherwise (decision 0066).
     *
     * @throws InvalidArgumentException
     */
    public function author(RequestContext $context, AuthorInterface $fromARequest): AuthorInterface
    {
        if (isset($this->properties['author'])) {
            return $this->object('author', AuthorInterface::class);
        }
        $administrator = $this->properties['administrator'] ?? null;
        if ($administrator instanceof Subject) {
            return new AnAdministrator($administrator);
        }
        if ($administrator !== null) {
            throw new InvalidArgumentException(sprintf('The administrator a body read back names is a subject, got %s.', get_debug_type($administrator)));
        }

        return $context->ipAddress === null ? new TheHost() : $fromARequest;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return list<mixed>
     */
    private function list(string $name): array
    {
        $value = $this->properties[$name] ?? null;
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidArgumentException(sprintf('The property "%s" of a body read back is a list, got %s.', $name, get_debug_type($value)));
        }

        return $value;
    }
}
