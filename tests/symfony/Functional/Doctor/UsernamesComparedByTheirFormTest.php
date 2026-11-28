<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctor;

use App\Doctor\UsernamesComparedByTheirForm;
use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use IntlChar;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function strpos;
use function substr;

final class UsernamesComparedByTheirFormTest extends DatabaseTestCase
{
    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function aTenantWhoseTagsAreDerivedUnderThisBuildAndWhoNamedNobodyIsGreen(): void
    {
        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [
                true,
                [sprintf(
                    'Every person of the tenant "%s" is found by the enforced form of their username, derivation 1 under Unicode %s.',
                    self::tenant()->slug,
                    IntlChar::UNICODE_VERSION,
                )],
            ],
            [$finding->green, $finding->lines],
        );
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    #[DataProvider('provideDerivationsNotCurrent')]
    public function aTenantWhoseTagsAreDerivedUnderAnotherDerivationIsRed(string $statement, string $under): void
    {
        // Given
        self::entityManager()->getConnection()->executeStatement($statement);

        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [
                false,
                sprintf(
                    'The tags of the persons of the tenant "%s" were derived %s, and this build derives them under derivation 1 and Unicode %s: a person whose username is not in its enforced form is found under it as written only, and no person is created or renamed.',
                    self::tenant()->slug,
                    $under,
                    IntlChar::UNICODE_VERSION,
                ),
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDerivationsNotCurrent(): iterable
    {
        yield 'none, as 0.1 left them' => ['DELETE FROM ' . BlindIndexDerivations::TABLE, 'under no recorded derivation, as 0.1 left them'];
        yield 'another version of Unicode' => [
            'UPDATE ' . BlindIndexDerivations::TABLE . " SET unicode_version = '15.1'",
            'under derivation 1 and Unicode 15.1',
        ];
    }

    /**
     * RFC 8265 §3.3, §3.3.4: the persons left with a username as written until 1.0.0, and those no lookup finds.
     */
    #[Test]
    public function aTenantWhoseLastReindexNamedPersonsIsRed(): void
    {
        // Given
        self::derivations()->record(self::tenant(), 1, 2);

        // When
        $finding = self::check()->finding();

        // Then
        static::assertSame(
            [
                false,
                '1 person(s) whose username RFC 8265 §3.3 refuses, who sign in under it as written until 1.0.0 and no later, and 2 person(s) whose usernames it compares as one, whom no lookup finds.',
            ],
            [$finding->green, substr($finding->lines[0] ?? '', (int) strpos($finding->lines[0] ?? '', '1 person(s)'))],
        );
    }

    private static function check(): UsernamesComparedByTheirForm
    {
        return self::service(UsernamesComparedByTheirForm::class, UsernamesComparedByTheirForm::class);
    }
}
