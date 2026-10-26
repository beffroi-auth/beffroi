<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use function array_map;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\KeyManagement\BlindIndex\Projection\Verbatim;
use function sprintf;

/**
 * The columns a search matches on once the column it searches is sealed, declared here and nowhere else
 * (decision 0011).
 *
 * A sealed column cannot be searched: the format seals every value under a random initialisation vector,
 * so two encryptions of one username differ and `WHERE username = ?` matches nothing. What is searched
 * instead is a keyed tag of the value, equal for equal values, in a sibling column the unique constraint
 * of the tenant also moves onto.
 *
 * **What a tag leaks, and why only these columns carry one.** Equal values give equal tags, so the column
 * says which rows share a value and how often each occurs; on a column with few distinct values that
 * recovers the values themselves by counting. A username, an address and the subject an upstream provider
 * gave are high-entropy and looked up by equality, which is what an index is for. `gender`, `locale`,
 * `zoneinfo` and `birthdate` are neither, and decision 0011 refuses an index on them in as many words; the
 * mapping says so where the next reader is, and nothing here lists them.
 *
 * The one index here that is not high-entropy is `provider`, a handful of values across a tenant, so its
 * column says which rows share a provider and the largest bucket is guessable outright. It carries one
 * because the unique constraint of its table is on the pair, not because anything looks a provider up on
 * its own, and that price is written in the mapping beside the constraint that asks for it.
 *
 * **One index key per tenant**, not one per column: a key per projection would be a second key the day a
 * tenant's keys are destroyed and a second thing to never rotate. Each column names its index after itself
 * all the same (`BlindIndexedColumn::index()`), so the tags are derived under subkeys that differ and a
 * username that happens to be an address does not share the tag of that address.
 */
final readonly class BlindIndexedColumns
{
    /**
     * The scope the index key of a tenant is minted under, a scope of its own because the age past which a
     * key is retired is a setting of a store and not of a scope: the families of columns retire their key
     * after thirty days, and an index key must never be retired at all, every tag already written having
     * been derived under it (decision 0018). It is not the name of a table and so cannot collide with a
     * family, which is one (`EncryptedColumnTypes`).
     */
    public const string SCOPE = 'blind_index';

    /**
     * @return list<BlindIndexedColumn>
     */
    public static function all(): array
    {
        return [
            // A username is indexed byte for byte, because it is what it is: folding its case here would
            // be a rule of the identity model and not of an index, and the model normalizes it already
            // (`User::normalizeUsername()`, which trims and nothing more).
            new BlindIndexedColumn(
                User::class,
                'username',
                'usernameIndex',
                new Verbatim(),
            ),
            // An address is folded whole, its local part as well as its domain: one mailbox, however its
            // local part is written, so that no second person holds the mailbox of a first and no upstream
            // provider has a person created with it verified (FoldedEmailAddress, issue #781).
            new BlindIndexedColumn(
                User::class,
                'email',
                'emailIndex',
                new FoldedEmailAddress(),
            ),
            // The pair a federated login recognises an identity by, and what the unique constraint of the
            // table is held on. Both byte for byte: what an upstream provider gave is compared as it gave
            // it, and the name of a provider is what the registration that trusts it wrote.
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
     * The properties that hold a tag, by the entity they are declared on: what the listener walks a flush
     * with, resolved once.
     *
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
     * The index of one property of one entity, for the caller that has a value to look up rather than a
     * row to write: a query matches the tag, and the projection it matches under has to be the one the
     * write used, which is why there is one declaration and not one per side.
     *
     * @param class-string $entity
     *
     * @throws InvalidArgumentException if that property carries no blind index
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
     * The name of every property a tag is written to, which is what a test holds against the mapping.
     *
     * @return list<string>
     */
    public static function tags(): array
    {
        return array_map(static fn (BlindIndexedColumn $column): string => $column->tag, self::all());
    }
}
