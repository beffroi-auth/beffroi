<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use function array_keys;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;
use Beffroi\Core\Exception\LogicException;
use function get_debug_type;
use function in_array;
use function is_string;
use ReflectionProperty;
use function sprintf;
use Stringable;

/**
 * The provider's own and not the BlindIndexed attribute of the bridge, which the entities of the core cannot carry.
 * A tag is derived when its row is inserted and when its value changes, so that an update leaves the tag of a person
 * beffroi:user:reindex set aside as it is; a row written through DBAL or changed by a bulk UPDATE keeps the tag it had.
 */
final class BlindIndexListener
{
    /**
     * @var array<class-string, list<array{ReflectionProperty, ReflectionProperty, BlindIndexedColumn}>>
     */
    private array $resolved = [];

    public function __construct(
        private readonly TenantBlindIndexes $indexes,
    ) {
    }

    public function onFlush(OnFlushEventArgs $event): void
    {
        $manager = $event->getObjectManager();
        $unitOfWork = $manager->getUnitOfWork();

        foreach ($unitOfWork->getScheduledEntityInsertions() as $entity) {
            $metadata = $manager->getClassMetadata($entity::class);
            if ($this->fill($entity, $metadata, null)) {
                $unitOfWork->recomputeSingleEntityChangeSet($metadata, $entity);
            }
        }
        foreach ($unitOfWork->getScheduledEntityUpdates() as $entity) {
            $metadata = $manager->getClassMetadata($entity::class);
            if ($this->fill($entity, $metadata, array_keys($unitOfWork->getEntityChangeSet($entity)))) {
                $unitOfWork->recomputeSingleEntityChangeSet($metadata, $entity);
            }
        }
    }

    /**
     * @param ClassMetadata<object> $metadata
     * @param list<string>|null $changed the properties an update changes, null for an insertion
     *
     * @return bool whether a tag was written
     */
    private function fill(object $entity, ClassMetadata $metadata, ?array $changed): bool
    {
        $written = false;

        foreach ($this->properties($metadata->getName()) as [$source, $target, $column]) {
            if (! $source->isInitialized($entity) || $changed !== null && ! in_array($column->value, $changed, true)) {
                continue;
            }

            $tag = $this->tag($source->getValue($entity), $column, $entity::class);

            if (! $target->isInitialized($entity) || $target->getValue($entity) !== $tag) {
                $target->setValue($entity, $tag);
                $written = true;
            }
        }

        return $written;
    }

    /**
     * @throws LogicException if the property holds something a keyed digest cannot be taken of
     */
    private function tag(mixed $value, BlindIndexedColumn $column, string $class): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value) && ! $value instanceof Stringable) {
            throw new LogicException(sprintf(
                'The property "%s::$%s" holds a value of type "%s", which no blind index can be derived from: a tag is a keyed digest of a string.',
                $class,
                $column->value,
                get_debug_type($value),
            ));
        }

        return $this->indexes->of($column)->of((string) $value);
    }

    /**
     * @param class-string $class
     *
     * @return list<array{ReflectionProperty, ReflectionProperty, BlindIndexedColumn}>
     *
     * @throws LogicException if a value that may be absent is indexed into a column that refuses null
     */
    private function properties(string $class): array
    {
        if (isset($this->resolved[$class])) {
            return $this->resolved[$class];
        }

        $resolved = [];
        foreach (BlindIndexedColumns::byEntity()[$class] ?? [] as $column) {
            $source = new ReflectionProperty($class, $column->value);
            $target = new ReflectionProperty($class, $column->tag);

            if (($source->getType()?->allowsNull() ?? true) && ! ($target->getType()?->allowsNull() ?? true)) {
                throw new LogicException(sprintf(
                    'The property "%s::$%s" may be absent, but "%s::$%s", which indexes it, refuses null: declare it nullable, or a user who gave no value could not be saved at all.',
                    $class,
                    $column->value,
                    $class,
                    $column->tag,
                ));
            }

            $resolved[] = [$source, $target, $column];
        }

        return $this->resolved[$class] = $resolved;
    }
}
