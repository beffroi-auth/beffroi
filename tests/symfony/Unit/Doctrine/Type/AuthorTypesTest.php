<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctrine\Type;

use App\Doctrine\Type\ClaimChangeAuthorType;
use App\Doctrine\Type\JournalAuthorType;
use App\Doctrine\Type\RowsOfAKind;
use App\Doctrine\Type\WrittenAuthorType;
use Beffroi\Core\Application\Author\Authors;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AdministratorKind;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AnUnauthenticatedCaller;
use Beffroi\Core\Domain\Author\AnUpstreamProvider;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ClientKind;
use Beffroi\Core\Domain\Author\DirectoryKind;
use Beffroi\Core\Domain\Author\HostKind;
use Beffroi\Core\Domain\Author\PersonKind;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\UnauthenticatedKind;
use Beffroi\Core\Domain\Author\UpstreamKind;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decisions 0060 and 0066
 */
final class AuthorTypesTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        WrittenAuthorType::resolveWith(new Authors([
            new PersonKind(),
            new AdministratorKind(),
            new ClientKind(),
            new DirectoryKind(),
            new UpstreamKind(),
            new UnauthenticatedKind(),
            new HostKind(),
        ]));
    }

    /**
     * @param class-string<WrittenAuthorType> $type
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function anAuthorGoesToTheColumnAsTheDocumentOfTheirKind(string $type, AuthorInterface $author, string $written): void
    {
        // When / Then
        static::assertSame($written, new $type()->convertToDatabaseValue($author, new PostgreSQLPlatform()));
    }

    /**
     * @param class-string<WrittenAuthorType> $type
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theDocumentOfAnAuthorComesBackAsTheAuthorItWas(string $type, AuthorInterface $author, string $written): void
    {
        // When / Then
        static::assertEquals($author, new $type()->convertToPHPValue($written, new PostgreSQLPlatform()));
    }

    /**
     * @return iterable<string, array{class-string<WrittenAuthorType>, AuthorInterface, string}>
     */
    public static function provideAuthors(): iterable
    {
        foreach ([JournalAuthorType::class => 'of an act', ClaimChangeAuthorType::class => 'of a change'] as $type => $of) {
            yield 'the person ' . $of => [$type, new ThePerson(), '{"kind":"person"}'];
            yield 'an administrator ' . $of => [
                $type,
                new AnAdministrator(new Subject('mallory-subject')),
                '{"kind":"administrator","subject":"mallory-subject"}',
            ];
            yield 'a client ' . $of => [$type, new AClient('oidc-demo'), '{"kind":"client","client_id":"oidc-demo"}'];
            yield 'a directory ' . $of => [$type, new ADirectory('Entra ID'), '{"kind":"directory","name":"Entra ID"}'];
            yield 'an upstream provider ' . $of => [$type, new AnUpstreamProvider('Acme SSO'), '{"kind":"upstream","name":"Acme SSO"}'];
            yield 'an unauthenticated caller ' . $of => [$type, new AnUnauthenticatedCaller(), '{"kind":"unauthenticated"}'];
            yield 'the host ' . $of => [$type, new TheHost(), '{"kind":"host"}'];
        }
    }

    /**
     * A row written before acts named the kind of their author.
     *
     * @param class-string<WrittenAuthorType> $type
     */
    #[Test]
    #[DataProvider('provideAuthorsWrittenBefore')]
    public function whatARowWrittenBeforeHoldsComesBackAsWhatItMeant(string $type, ?string $written, ?AuthorInterface $read): void
    {
        // When / Then
        static::assertEquals($read, new $type()->convertToPHPValue($written, new PostgreSQLPlatform()));
    }

    /**
     * @return iterable<string, array{class-string<WrittenAuthorType>, string|null, AuthorInterface|null}>
     */
    public static function provideAuthorsWrittenBefore(): iterable
    {
        yield 'an act an administrator did, by their bare subject' => [
            JournalAuthorType::class,
            'mallory-subject',
            new AnAdministrator(new Subject('mallory-subject')),
        ];
        yield 'an act the person or the host did, which its provenance tells apart' => [JournalAuthorType::class, null, null];
        yield 'a change an administrator made, by their bare subject' => [
            ClaimChangeAuthorType::class,
            'mallory-subject',
            new AnAdministrator(new Subject('mallory-subject')),
        ];
        yield 'a change the person made' => [ClaimChangeAuthorType::class, null, new ThePerson()];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideColumnsThatNameNoAuthor(): iterable
    {
        yield 'a document of no kind this provider writes' => ['{"kind":"operator"}'];
        yield 'a document that is not JSON' => ['{"kind":"person"'];
        yield 'a document that is not an object' => ['{'];
        yield 'a bare subject that is not one' => ['two words'];
    }

    #[Test]
    #[DataProvider('provideColumnsThatNameNoAuthor')]
    public function aColumnThatNamesNoAuthorIsRefused(string $written): void
    {
        // Then
        $this->expectException(ValueNotConvertible::class);

        // When
        new JournalAuthorType()->convertToPHPValue($written, new PostgreSQLPlatform());
    }

    /**
     * Every document begins with its kind, which the pattern of a kind stops right after; a row written before acts
     * named the kind of their author holds an administrator by a bare subject, and the person of a change by NULL.
     *
     * @param class-string<WrittenAuthorType> $type
     */
    #[Test]
    #[DataProvider('provideRowsOfAKind')]
    public function theRowsOfAKindAreItsDocumentsAndWhatARowWrittenBeforeHeldOfIt(string $type, string $kind, RowsOfAKind $rows): void
    {
        // When / Then
        static::assertEquals($rows, new $type()->rowsOfKind($kind));
    }

    /**
     * @return iterable<string, array{class-string<WrittenAuthorType>, string, RowsOfAKind}>
     */
    public static function provideRowsOfAKind(): iterable
    {
        yield 'the administrators of the journal' => [JournalAuthorType::class, 'administrator', new RowsOfAKind('{"kind":"administrator"%', '{%', false)];
        yield 'the person of the journal' => [JournalAuthorType::class, 'person', new RowsOfAKind('{"kind":"person"%', null, false)];
        yield 'the host of the journal' => [JournalAuthorType::class, 'host', new RowsOfAKind('{"kind":"host"%', null, false)];
        yield 'the administrators of the history' => [ClaimChangeAuthorType::class, 'administrator', new RowsOfAKind('{"kind":"administrator"%', '{%', false)];
        yield 'the person of the history' => [ClaimChangeAuthorType::class, 'person', new RowsOfAKind('{"kind":"person"%', null, true)];
    }

    #[Test]
    public function aKindThatIsNotLowercaseLettersIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A kind of author names itself in lowercase letters, not "admin%".');

        // When
        new JournalAuthorType()->rowsOfKind('admin%');
    }

    #[Test]
    public function theColumnIsTextOnEachPlatform(): void
    {
        // When / Then
        static::assertSame(
            ['TEXT', 'CLOB'],
            [
                new JournalAuthorType()->getSQLDeclaration([], new PostgreSQLPlatform()),
                new ClaimChangeAuthorType()->getSQLDeclaration([], new SQLitePlatform()),
            ],
        );
    }
}
