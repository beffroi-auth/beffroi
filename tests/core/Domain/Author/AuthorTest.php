<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Author;

use Beffroi\Core\Domain\Author\AnUnauthenticatedCaller;
use Beffroi\Core\Domain\Author\AnUpstreamProvider;
use Beffroi\Core\Domain\Author\ToldByItsNameInterface;
use Beffroi\Core\Domain\Author\AClient;
use Beffroi\Core\Domain\Author\ADirectory;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\ThePerson;
use Beffroi\Core\Domain\Author\ToldByItsRoleInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class AuthorTest extends TestCase
{
    /**
     * Decisions 0038 and 0066: the person is told the role of an administrator and of the host, never who they are or
     * where they were.
     */
    #[Test]
    #[DataProvider('provideAuthors')]
    public function anAdministratorAndTheHostAreToldByTheirRole(AuthorInterface $author, bool $byTheirRole): void
    {
        // When / Then
        static::assertSame($byTheirRole, $author instanceof ToldByItsRoleInterface);
    }

    /**
     * @return iterable<string, array{AuthorInterface, bool}>
     */
    public static function provideAuthors(): iterable
    {
        yield 'the person' => [new ThePerson(), false];
        yield 'an administrator' => [new AnAdministrator(new Subject('administrator-subject')), true];
        yield 'a client' => [new AClient('oidc-demo'), false];
        yield 'a directory' => [new ADirectory('Entra ID'), false];
        yield 'an upstream provider' => [new AnUpstreamProvider('Acme SSO'), false];
        yield 'an unauthenticated caller' => [new AnUnauthenticatedCaller(), false];
        yield 'the host' => [new TheHost(), true];
    }

    /**
     * Decision 0066: the person is told the name of a directory and of an upstream provider.
     */
    #[Test]
    #[DataProvider('provideAuthorsToldByTheirName')]
    public function aDirectoryAndAnUpstreamProviderAreToldByTheirName(ToldByItsNameInterface $author, string $name): void
    {
        // When / Then
        static::assertSame($name, $author->name());
    }

    /**
     * @return iterable<string, array{ToldByItsNameInterface, string}>
     */
    public static function provideAuthorsToldByTheirName(): iterable
    {
        yield 'a directory' => [new ADirectory('Entra ID'), 'Entra ID'];
        yield 'an upstream provider' => [new AnUpstreamProvider('Acme SSO'), 'Acme SSO'];
    }

    /**
     * Decision 0063
     */
    #[Test]
    #[DataProvider('provideNamesOfNoDirectory')]
    public function aDirectoryIsNamedByPlainTextThatIsNeverBlank(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A directory is named by the name the deployment declares it under, plain text and never blank.');

        // When
        new ADirectory($name);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesOfNoDirectory(): iterable
    {
        yield 'empty' => [''];
        yield 'blank' => ['   '];
        yield 'blank in another script' => ["\u{3000}\u{00A0}"];
        yield 'a line feed' => ["Entra\nID"];
        yield 'a right-to-left override' => ["Entra \u{202E}DI"];
        yield 'longer than plain text holds' => [str_repeat('d', 256)];
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function anUpstreamProviderIsNamedByPlainTextThatIsNeverBlank(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An upstream provider is named by the name the deployment declares it under, plain text and never blank.');

        // When
        new AnUpstreamProvider("\u{2003}");
    }

    /**
     * RFC 7009 §2.1, RFC 7592 §2.3
     */
    #[Test]
    #[DataProvider('provideIdentifiersOfNoClient')]
    public function aClientIsNamedByAnIdentifierThatIsPlainText(string $clientId): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A client that acts is named by the identifier it was registered under.');

        // When
        new AClient($clientId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIdentifiersOfNoClient(): iterable
    {
        yield 'empty' => [''];
        yield 'a control character' => ["oidc\x00demo"];
    }
}
