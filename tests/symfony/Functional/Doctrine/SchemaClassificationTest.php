<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_keys;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ProviderSchema;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedSchema;
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
 * Decision 0011
 */
final class SchemaClassificationTest extends DatabaseTestCase
{
    private const int TABLES = 41;

    private const int COLUMNS = 413;

    #[Test]
    public function everyColumnOfEveryTableIsClassified(): void
    {
        // Given
        $schema = ProviderSchema::columns(self::entityManager(), EncryptedColumnTypes::familyByType());

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

    #[Test]
    public function theTableOfTheDataKeyStoreIsClassifiedToo(): void
    {
        // When / Then
        static::assertSame(
            ['binding', 'client', 'id', 'key_material', 'master_key_id', 'scope'],
            array_keys(self::model()->linesOf('beffroi_data_key')),
        );
    }

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
     * Decision 0011
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
     * Decision 0011
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

    #[Test]
    public function everyFamilyTheProviderDeclaresSealsAColumn(): void
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
