<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ClaimChangeTest extends TestCase
{
    #[Test]
    public function aChangeHoldsBothValuesAndTheTenantOfThePerson(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $change = self::change($user, 'Ada', 'Augusta');

        // Then
        static::assertSame('Ada', $change->was);
        static::assertSame('Augusta', $change->became);
        static::assertTrue($change->tenant->equals($user->tenant));
    }

    #[Test]
    #[DataProvider('provideOneSide')]
    public function aClaimFilledInOrTakenBackIsAChange(?string $was, ?string $became): void
    {
        // When / Then
        static::assertSame($was, self::change(null, $was, $became)->was);
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideOneSide(): iterable
    {
        yield 'filled in for the first time' => [null, 'Ada'];
        yield 'taken back' => ['Ada', null];
    }

    #[Test]
    public function aClaimThatSaidNothingAndSaysNothingDidNotChange(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A change of a claim is a change');

        // When
        self::change(null, null, null);
    }

    #[Test]
    public function aValueThatDidNotChangeIsNotAChange(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('the value it had and the value it has are the same');

        // When
        self::change(null, 'Ada', 'Ada');
    }

    #[Test]
    public function aChangeNamesTheClaimItIsAbout(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A change of a claim names the claim.');

        // When
        new ClaimChange(Uuid::v7(), Fixtures::user(), '', 'Ada', 'Augusta', Fixtures::now(), Fixtures::context(), new ThePerson());
    }

    private static function change(?User $user, ?string $was, ?string $became): ClaimChange
    {
        return new ClaimChange(
            Uuid::v7(),
            $user ?? Fixtures::user(),
            'nickname',
            $was,
            $became,
            Fixtures::now(),
            Fixtures::context(),
            new ThePerson(),
        );
    }
}
