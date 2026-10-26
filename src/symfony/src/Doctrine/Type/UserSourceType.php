<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Exception\InvalidArgumentException;
use Doctrine\DBAL\Platforms\AbstractPlatform;

/**
 * The source that created a person and the claims it holds (decision 0002), as one JSON column.
 *
 * **A local source is a null column, and a null column is a local source.** A local source holds nothing
 * and writes no document (`UserSource::toDocument()`), so there is nothing to seal; and the column comes to
 * a table that already holds people, every one of them created by a console, a fixture or an import, which
 * a migration can say without the data key of their tenant, which it does not have.
 *
 * @extends JsonObjectType<UserSource>
 */
final class UserSourceType extends JsonObjectType
{
    public const string NAME = 'beffroi_user_source';

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value instanceof UserSource && $value->isLocal()) {
            return null;
        }

        return parent::convertToDatabaseValue($value, $platform);
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): UserSource
    {
        return parent::convertToPHPValue($value, $platform) ?? UserSource::local();
    }

    protected function encode(object $value): array
    {
        return $value->toDocument() ?? throw new InvalidArgumentException('A local source writes no document.');
    }

    protected function decode(array $data): object
    {
        return UserSource::fromDocument($data);
    }

    protected function expects(): string
    {
        return UserSource::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
