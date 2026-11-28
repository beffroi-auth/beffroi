<?php

declare(strict_types=1);

namespace App\Doctrine\Listener;

use Beffroi\Core\Exception\LogicException;
use DateTimeInterface;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Event\PostUpdateEventArgs;
use function is_array;
use function is_int;
use function spl_object_id;
use function sprintf;

/**
 * Raises the version and moves the last change of a row from what the row holds, never from what the entity was loaded
 * with, then gives both back to the entity: two writers that loaded one version raise it twice, and neither the version
 * nor the last change goes back (RFC 7644 §3.14, RFC 9110 §8.8.1 and §13.1.1). The mapping leaves both columns out of
 * every UPDATE Doctrine writes, and the statement here runs in the transaction of the flush, under the lock of the row.
 */
final class VersionRaisedInTheRow
{
    private const string VERSION = 'version';

    private const string UPDATED_AT = 'updatedAt';

    /**
     * @throws LogicException when the version did not rise or the row has gone
     */
    public function postUpdate(object $entity, PostUpdateEventArgs $event): void
    {
        $manager = $event->getObjectManager();
        $unitOfWork = $manager->getUnitOfWork();
        $change = $unitOfWork->getEntityChangeSet($entity)[self::VERSION] ?? null;
        if (! is_array($change)) {
            return;
        }
        [$was, $is] = $change;
        if (! is_int($was) || ! is_int($is) || $is <= $was) {
            throw new LogicException(sprintf('The version of a %s only rises.', $entity::class));
        }
        $metadata = $manager->getClassMetadata($entity::class);
        $connection = $manager->getConnection();
        $identifier = $metadata->getSingleIdentifierFieldName();
        $id = $metadata->getFieldValue($entity, $identifier);
        $idType = $metadata->getTypeOfField($identifier) ?? Types::STRING;
        $versionType = $metadata->getTypeOfField(self::VERSION) ?? Types::INTEGER;
        $atType = $metadata->getTypeOfField(self::UPDATED_AT) ?? Types::DATETIME_IMMUTABLE;
        $at = $metadata->getFieldValue($entity, self::UPDATED_AT);
        $table = $metadata->getTableName();
        $version = $metadata->getColumnName(self::VERSION);
        $updatedAt = $metadata->getColumnName(self::UPDATED_AT);
        $idColumn = $metadata->getColumnName($identifier);

        $connection->executeStatement(
            sprintf('UPDATE %1$s SET %2$s = %2$s + ?, %3$s = CASE WHEN %3$s < ? THEN ? ELSE %3$s END WHERE %4$s = ?', $table, $version, $updatedAt, $idColumn),
            [$is - $was, $at, $at, $id],
            [$versionType, $atType, $atType, $idType],
        );
        $row = $connection->fetchNumeric(sprintf('SELECT %s, %s FROM %s WHERE %s = ?', $version, $updatedAt, $table, $idColumn), [$id], [$idType]);
        if ($row === false) {
            throw new LogicException(sprintf('The row of a %s was written and is gone.', $entity::class));
        }
        $platform = $connection->getDatabasePlatform();
        $types = $connection->getConfiguration()->getTypeProvider();
        $read = [
            self::VERSION => $types->get($versionType)->convertToPHPValue($row[0], $platform),
            self::UPDATED_AT => $types->get($atType)->convertToPHPValue($row[1], $platform),
        ];
        if (! is_int($read[self::VERSION]) || ! $read[self::UPDATED_AT] instanceof DateTimeInterface) {
            throw new LogicException(sprintf('The row of a %s holds no version or no last change.', $entity::class));
        }
        foreach ($read as $field => $value) {
            $metadata->setFieldValue($entity, $field, $value);
            $unitOfWork->setOriginalEntityProperty(spl_object_id($entity), $field, $value);
        }
    }
}
