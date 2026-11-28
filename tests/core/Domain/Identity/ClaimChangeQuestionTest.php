<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\ClaimChange;
use Beffroi\Core\Domain\Identity\ClaimChangeQuestion;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class ClaimChangeQuestionTest extends TestCase
{
    #[Test]
    public function aQuestionThatAsksNothingAdmitsEveryChange(): void
    {
        // When / Then
        static::assertTrue(new ClaimChangeQuestion()->admits(self::change()));
    }

    #[Test]
    #[DataProvider('provideChanges')]
    public function theDaysAskedForAdmitWhatChangedOnThem(string $changedAt, bool $admitted): void
    {
        // Given
        $question = new ClaimChangeQuestion(period: Period::ofDays(Fixtures::now(), Fixtures::now()));

        // When / Then
        static::assertSame($admitted, $question->admits(self::change(changedAt: Fixtures::now()->modify($changedAt))));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideChanges(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    #[Test]
    #[DataProvider('provideClaims')]
    public function theClaimAskedForAdmitsTheChangesOfIt(string $claim, bool $admitted): void
    {
        // When / Then
        static::assertSame($admitted, new ClaimChangeQuestion(claim: $claim)->admits(self::change()));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideClaims(): iterable
    {
        yield 'the claim that changed' => ['given_name', true];
        yield 'another claim' => ['family_name', false];
    }

    /**
     * Decision 0066
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theKindOfAuthorAskedForAdmitsTheChangesItsAuthorsMade(string $by, AuthorInterface $author, bool $admitted): void
    {
        // When / Then
        static::assertSame($admitted, new ClaimChangeQuestion(by: $by)->admits(self::change(author: $author)));
    }

    /**
     * @return iterable<string, array{string, AuthorInterface, bool}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'an administrator asked, one made it' => ['administrator', new AnAdministrator(new Subject('admin-subject')), true];
        yield 'an administrator asked, the person made it' => ['administrator', new ThePerson(), false];
        yield 'the person asked, they made it' => ['person', new ThePerson(), true];
        yield 'the person asked, an administrator made it' => ['person', new AnAdministrator(new Subject('admin-subject')), false];
        yield 'a directory asked, one made it' => ['directory', new ADirectory('Entra ID'), true];
        yield 'the host asked, it made it' => ['host', new TheHost(), true];
        yield 'the host asked, a directory made it' => ['host', new ADirectory('Entra ID'), false];
    }

    private static function change(?DateTimeImmutable $changedAt = null, AuthorInterface $author = new ThePerson()): ClaimChange
    {
        return new ClaimChange(Uuid::v7(), Fixtures::user(), 'given_name', 'Ada', 'Augusta', $changedAt ?? Fixtures::now(), Fixtures::context(), $author);
    }
}
