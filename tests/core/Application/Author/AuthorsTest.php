<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Author;

use Beffroi\Core\Application\Author\Authors;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AdministratorKind;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ClientKind;
use Beffroi\Core\Domain\Author\DirectoryKind;
use Beffroi\Core\Domain\Author\HostKind;
use Beffroi\Core\Domain\Author\PersonKind;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthorsTest extends TestCase
{
    /**
     * Decision 0066
     *
     * @param array<string, string> $document
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function anAuthorIsWrittenByTheDocumentOfItsKind(AuthorInterface $author, array $document): void
    {
        // When / Then
        static::assertSame($document, $author->toDocument());
    }

    /**
     * Decision 0066
     *
     * @param array<string, string> $document
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function theDocumentOfAnAuthorReadsBackAsTheAuthorItWas(AuthorInterface $author, array $document): void
    {
        // When
        $read = self::authors()->fromDocument($document);

        // Then
        static::assertEquals($author, $read);
    }

    /**
     * @return iterable<string, array{AuthorInterface, array<string, string>}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the person' => [new ThePerson(), ['kind' => 'person']];
        yield 'an administrator, by the subject of their account' => [
            new AnAdministrator(new Subject('administrator-subject')),
            ['kind' => 'administrator', 'subject' => 'administrator-subject'],
        ];
        yield 'a client, by its identifier' => [new AClient('oidc-demo'), ['kind' => 'client', 'client_id' => 'oidc-demo']];
        yield 'a directory, by its name' => [new ADirectory('Entra ID'), ['kind' => 'directory', 'name' => 'Entra ID']];
        yield 'the host' => [new TheHost(), ['kind' => 'host']];
    }

    /**
     * Decision 0066
     *
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsOfNoAuthor')]
    public function aDocumentThatNamesNoAuthorIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        self::authors()->fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideDocumentsOfNoAuthor(): iterable
    {
        yield 'no kind' => [['subject' => 'administrator-subject'], '"" is no kind of author this provider writes.'];
        yield 'a kind nobody wired' => [['kind' => 'operator'], '"operator" is no kind of author this provider writes.'];
        yield 'a kind that is not a word' => [['kind' => ['administrator']], 'The member "kind" must be a string or absent.'];
        yield 'an administrator without their subject' => [['kind' => 'administrator'], 'An administrator who acted is named by the subject of their account.'];
        yield 'a client without its identifier' => [['kind' => 'client'], 'A client that acted is named by the identifier it was registered under.'];
        yield 'a directory without its name' => [['kind' => 'directory'], 'A directory that acted is named by the name the deployment declares it under.'];
        yield 'an administrator named by a subject that is not one' => [
            ['kind' => 'administrator', 'subject' => 'two words'],
            'The subject "two words" must be made of printable ASCII characters without spaces.',
        ];
    }

    #[Test]
    public function twoKindsOfOneNameAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two kinds of author give themselves the name "person".');

        // When
        new Authors([new PersonKind(), new PersonKind()]);
    }

    private static function authors(): Authors
    {
        return new Authors([new PersonKind(), new AdministratorKind(), new ClientKind(), new DirectoryKind(), new HostKind()]);
    }
}
