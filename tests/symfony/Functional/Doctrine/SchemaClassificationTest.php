<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use function array_keys;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\BundleSchema;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedModel;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\ClassifiedSchema;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\PersonalData\BlindIndex;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Owed;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
use function count;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function sort;

/**
 * Decision 0011: "Toute colonne à venir qui porte une donnée personnelle, par construction : un test
 * énumère les colonnes du schéma et refuse une colonne qui n'est ni déclarée hors données personnelles,
 * ni d'un type chiffré. Une colonne nouvelle est classée ou le test est rouge."
 *
 * The classification is the model's own, field by field, in the package that owns the entity
 * (`ClassifiedFieldsInterface`); `ClassifiedModel` reads it against the mappings and `ClassifiedSchema` is
 * the walk. This holds the two against the schema Doctrine builds, and shows on a model of its own what
 * each kind of line refuses.
 */
final class SchemaClassificationTest extends DatabaseTestCase
{
    /**
     * How many tables and columns the schema holds, written out so that a table added whole, or a column
     * added to one, is a figure to change here and a line to add on the class that holds the field. All
     * but one are described by a mapping of the bundle; the last is the table of the data key store, which
     * the listener of the ORM bridge puts in the schema the ORM assembles (decisions 0011 and 0018).
     */
    private const int TABLES = 35;

    private const int COLUMNS = 356;

    #[Test]
    public function everyColumnOfEveryTableIsClassified(): void
    {
        // Given
        $schema = BundleSchema::columns(self::entityManager(), EncryptedColumnTypes::familyByType());

        // When / Then
        static::assertSame([], new ClassifiedSchema(self::model())->findings($schema));
    }

    #[Test]
    public function theModelClassifiesAsManyTablesAndColumnsAsTheMappingsDescribe(): void
    {
        // Given
        $model = self::model();

        // When / Then
        static::assertCount(self::TABLES, $model->tables());
        static::assertSame(self::COLUMNS, $model->columnCount());
    }

    /**
     * The one table of the schema no class of the model holds a field of, classified by the bundle that
     * puts it there: it is in the walk like any other, and the figures above count it.
     */
    #[Test]
    public function theTableOfTheDataKeyStoreIsClassifiedToo(): void
    {
        // When / Then
        static::assertSame(
            ['binding', 'client', 'id', 'key_material', 'master_key_id', 'scope'],
            array_keys(self::model()->linesOf('beffroi_data_key')),
        );
    }

    /**
     * A column of an entity whose field no line names, named with the field the line goes on: nothing is
     * deduced from a name, so the column of a field somebody added and did not classify is red the day it
     * is mapped.
     */
    #[Test]
    public function aColumnTheSchemaDeclaresAndTheModelDoesNotClassifyIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_user' => ['id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM)]],
            ['beffroi_user.favourite_colour' => User::class . '::$favouriteColour'],
        ));

        // When
        $findings = $classification->findings([
            'beffroi_user' => [
                'id' => null,
                'favourite_colour' => null,
            ],
        ]);

        // Then
        static::assertSame(
            [
                'beffroi_user.favourite_colour is in the schema and the model does not classify it: declare Beffroi\Core\Domain\Identity\User::$favouriteColour readable with the reason a dump of it gives nothing away, sealed under its family, a blind index, or owed to the issue that seals it.',
            ],
            $findings,
        );
    }

    /**
     * A table added whole is every one of its columns classified by nobody, and no field of the model
     * behind any of them, so it is refused column by column.
     */
    #[Test]
    public function aTableTheSchemaDeclaresAndNoClassOfTheModelHoldsIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel([]));

        // When
        $findings = $classification->findings([
            'beffroi_new_table' => [
                'id' => null,
                'tenant_id' => null,
            ],
        ]);

        // Then
        static::assertCount(2, $findings);
    }

    #[Test]
    public function aFieldOwedToAnIssueAndFoundSealedIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_user' => ['email' => new Owed('beffroi#402', 'the electronic address of a person')]],
        ));

        // When
        $findings = $classification->findings(['beffroi_user' => ['email' => 'user']]);

        // Then
        static::assertSame(
            [
                'beffroi_user.email is sealed and beffroi#402 still owes it ("the electronic address of a person"): delete its line and declare it sealed.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aFieldDeclaredSealedAndFoundInTheClearIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_user' => ['email' => new Sealed('user')]],
        ));

        // When
        $findings = $classification->findings(['beffroi_user' => ['email' => null]]);

        // Then
        static::assertSame(
            [
                'beffroi_user.email is declared sealed under the "user" family and what stores it does not seal it.',
            ],
            $findings,
        );
    }

    /**
     * A field seals under its own table, the family being the name of the table without the prefix of the
     * bundle: a field sealed under another family is a value written into the scope of a table that is not
     * its own, which no destruction of its tenant's keys for that table would reach.
     */
    #[Test]
    public function aFieldDeclaredSealedUnderAnotherTableIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_interaction' => ['login_hint' => new Sealed('user')]],
        ));

        // When
        $findings = $classification->findings(['beffroi_interaction' => ['login_hint' => 'user']]);

        // Then
        static::assertSame(
            [
                'beffroi_interaction.login_hint is declared sealed under the "user" family, and a field seals under its own table, so under "interaction".',
            ],
            $findings,
        );
    }

    /**
     * And the shape of the mapping that produces it without showing it: an embeddable fixes the type of
     * each of its fields once for the whole model, so a second entity embedding an object whose field
     * seals lands that field's column, with that type, on a table of another family.
     */
    #[Test]
    public function aFieldSealedUnderTheFamilyOfAnotherTableIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_consent' => ['login_hint' => new Sealed('consent')]],
        ));

        // When
        $findings = $classification->findings(['beffroi_consent' => ['login_hint' => 'interaction']]);

        // Then
        static::assertSame(
            [
                'beffroi_consent.login_hint is declared sealed under the "consent" family and is sealed under "interaction", which is another family: a field of an embeddable several entities embed cannot carry the type of one of their tables.',
            ],
            $findings,
        );
    }

    #[Test]
    public function aFieldDeclaredReadableAndFoundSealedIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_user' => ['id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM)]],
        ));

        // When
        $findings = $classification->findings(['beffroi_user' => ['id' => 'user']]);

        // Then
        static::assertSame(
            [
                'beffroi_user.id is sealed, and is declared readable ("' . Reason::DRAWN_AT_RANDOM . '"): declare it sealed under its family.',
            ],
            $findings,
        );
    }

    /**
     * A tag is matched as it was written, so sealing it would leave the column it indexes with no way of
     * being looked up at all.
     */
    #[Test]
    public function aBlindIndexFoundSealedIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_user' => ['username_index' => new BlindIndex()]],
        ));

        // When
        $findings = $classification->findings(['beffroi_user' => ['username_index' => 'user']]);

        // Then
        static::assertSame(
            [
                'beffroi_user.username_index is a blind index and is sealed: a tag is matched as it was written, so it is written in the clear.',
            ],
            $findings,
        );
    }

    /**
     * A line the schema gives no column: the field was renamed or dropped, and the line that was written
     * for it cannot outlive it.
     */
    #[Test]
    public function aLineNoColumnOfTheSchemaCarriesIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_user' => ['id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM)]],
            [],
            [User::class . '::$pagerNumber'],
        ));

        // When
        $findings = $classification->findings(['beffroi_user' => ['id' => null]]);

        // Then
        static::assertSame(
            [
                'Beffroi\Core\Domain\Identity\User::$pagerNumber is classified and no column of the schema carries it: delete its line.',
            ],
            $findings,
        );
    }

    /**
     * And the same for the table the bundle classifies by the column, which has no field to be named by:
     * a line of it the table does not carry is refused as any other.
     */
    #[Test]
    public function aLineWhoseColumnTheSchemaNoLongerDeclaresIsRefused(): void
    {
        // Given
        $classification = new ClassifiedSchema(new ClassifiedModel(
            ['beffroi_data_key' => ['binding' => new NoPersonalDatum(Reason::NAMES_NO_PERSON)]],
        ));

        // When
        $findings = $classification->findings(['beffroi_data_key' => []]);

        // Then
        static::assertSame(
            [
                'beffroi_data_key.binding is classified and the schema does not declare it: delete its line.',
            ],
            $findings,
        );
    }

    /**
     * Decision 0011 gives the reasons a column stays readable, and a reason is read by a person: it is a
     * sentence, and not the name of a category.
     */
    #[Test]
    public function theReasonOfEveryReadableColumnIsASentence(): void
    {
        // When / Then
        foreach (self::model()->columns() as $table => $columns) {
            foreach ($columns as $column => $line) {
                if (! $line instanceof NoPersonalDatum) {
                    continue;
                }
                static::assertGreaterThanOrEqual(5, count(explode(' ', $line->reason)), $table . '.' . $column);
            }
        }
    }

    /**
     * The four reasons decision 0011 writes down, each of them the whole truth of at least one column of
     * the schema as it stands.
     */
    #[Test]
    #[DataProvider('provideReasonsOfDecision0011')]
    public function eachReasonOfDecision0011ClassifiesAColumn(string $reason): void
    {
        // When
        $columns = [];
        foreach (self::model()->columns() as $table => $lines) {
            foreach ($lines as $column => $line) {
                if ($line instanceof NoPersonalDatum && $line->reason === $reason) {
                    $columns[] = $table . '.' . $column;
                }
            }
        }

        // Then
        static::assertNotSame([], $columns, $reason);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideReasonsOfDecision0011(): iterable
    {
        yield 'hashed' => [Reason::HASHED];

        yield 'random' => [Reason::DRAWN_AT_RANDOM];

        yield 'public by construction' => [Reason::PUBLIC_BY_CONSTRUCTION];

        yield 'names no person' => [Reason::NAMES_NO_PERSON];
    }

    /**
     * Every family the bundle declares seals at least one column of the schema. A family is a scope, and a
     * scope is a data key per tenant: one that no column seals under is a key minted for nothing, or a
     * declaration left behind by a column that moved. The count is read from the declaration of the types
     * and the families from what the model declares, so neither can be the only one to know.
     */
    #[Test]
    public function everyFamilyTheBundleDeclaresSealsAColumn(): void
    {
        // Given
        $sealing = [];
        foreach (self::model()->columns() as $columns) {
            foreach ($columns as $line) {
                if ($line instanceof Sealed) {
                    $sealing[$line->family] = true;
                }
            }
        }

        // When
        $families = array_keys($sealing);
        sort($families);

        // Then
        $declared = EncryptedColumnTypes::families();
        sort($declared);
        static::assertSame(
            $declared,
            $families,
            'A family is declared and no column seals under it, or a column seals under a family nothing declares.',
        );
    }

    /**
     * The "known" list of CONFORMANCE_PLANS carries the issue that closes each gap, and so does an owed
     * line: one with no issue is a column nobody has undertaken to seal.
     */
    #[Test]
    public function everyOwedColumnNamesTheIssueThatSealsIt(): void
    {
        // When / Then
        foreach (self::model()->columns() as $table => $columns) {
            foreach ($columns as $column => $line) {
                if (! $line instanceof Owed) {
                    continue;
                }
                static::assertSame(1, preg_match('/^beffroi#\d+$/', $line->issue), $table . '.' . $column);
                static::assertGreaterThanOrEqual(5, count(explode(' ', $line->reason)), $table . '.' . $column);
            }
        }
    }

    private static function model(): ClassifiedModel
    {
        return ClassifiedModel::of(self::entityManager());
    }
}
