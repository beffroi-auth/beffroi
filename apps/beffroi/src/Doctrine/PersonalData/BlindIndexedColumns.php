<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use function array_map;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\KeyManagement\BlindIndex\Projection\Verbatim;
use function sprintf;

/**
 * Only values of high entropy carry a tag: equal values give equal tags, and a column of few distinct values would
 * give them away by counting (decision 0011).
 */
final readonly class BlindIndexedColumns
{
    /**
     * Not the name of a table, so that it cannot collide with a family of EncryptedColumnTypes.
     */
    public const string SCOPE = 'blind_index';

    /**
     * What the tags of this build are derived under, raised whenever a projection changes what a column indexes. A
     * tenant records it, with the version of Unicode the profile of a username reads, once every tag of its persons is
     * derived under it (BlindIndexDerivations); no tag of 0.1 was derived under any.
     */
    public const int DERIVATION = 1;

    /**
     * @return list<BlindIndexedColumn>
     */
    public static function all(): array
    {
        return [
            new BlindIndexedColumn(
                User::class,
                'username',
                'usernameIndex',
                new CaseMappedUsername(),
            ),
            new BlindIndexedColumn(
                User::class,
                'email',
                'emailIndex',
                new FoldedEmailAddress(),
            ),
            // Indexed because the unique constraint holds the pair, and compared byte for byte, as the upstream
            // provider gave it.
            new BlindIndexedColumn(
                LinkedIdentity::class,
                'provider',
                'providerIndex',
                new Verbatim(),
            ),
            new BlindIndexedColumn(
                LinkedIdentity::class,
                'subject',
                'subjectIndex',
                new Verbatim(),
            ),
        ];
    }

    /**
     * The username as it was written, as 0.1 indexed it, which a lookup tries first.
     */
    public static function usernameAsWritten(): BlindIndexedColumn
    {
        return new BlindIndexedColumn(User::class, 'username', 'usernameIndex', new Verbatim(), 'usernameIndex as written');
    }

    /**
     * @return array<class-string, list<BlindIndexedColumn>>
     */
    public static function byEntity(): array
    {
        $columns = [];
        foreach (self::all() as $column) {
            $columns[$column->entity][] = $column;
        }

        return $columns;
    }

    /**
     * @param class-string $entity
     *
     * @throws InvalidArgumentException
     */
    public static function of(string $entity, string $property): BlindIndexedColumn
    {
        foreach (self::byEntity()[$entity] ?? [] as $column) {
            if ($column->value === $property) {
                return $column;
            }
        }

        throw new InvalidArgumentException(sprintf('No blind index is declared on "%s::$%s", so nothing can be searched by it.', $entity, $property));
    }

    /**
     * @return list<string>
     */
    public static function tags(): array
    {
        return array_map(static fn (BlindIndexedColumn $column): string => $column->tag, self::all());
    }
}
