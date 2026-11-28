<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Administration;

use function array_diff;
use function array_keys;
use function array_values;
use function basename;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Oidc\Domain\Administration\ReadsByAnAdministrator;
use Beffroi\Oidc\Domain\Consent\ConsentActs;
use Beffroi\Oidc\Domain\EndSession\SessionEndActs;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use function class_exists;
use function dirname;
use function glob;
use function is_a;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function sort;
use function sprintf;

final class ReadsByAnAdministratorTest extends TestCase
{
    /**
     * The acts of a person that name an administrator and that the page of their acts does not list, each with the
     * reason: their archive holds them, saying an administrator did it.
     */
    private const array OFF_THE_PAGE = [
        LogoutTokenIssued::NAME => 'an application told of a session the administrator ended, which no page of the person lists whoever ended it',
        LogoutTokenGivenUp::NAME => 'the same telling given up',
    ];

    /**
     * Decision 0038: the person reads on the page of their acts that an administrator read or changed them. An act of
     * the tenant alone, an initial access token or a client, is on no page of a person.
     */
    #[Test]
    public function everyActOfAPersonThatNamesAnAdministratorIsOnTheirPageOrIsNamedAsOffIt(): void
    {
        // Given
        $onThePage = [
            ...ReadsByAnAdministrator::NAMES,
            ...ConsentActs::NAMES,
            ...SessionEndActs::NAMES,
            ...array_keys(self::OFF_THE_PAGE),
        ];

        // When
        $named = self::actsOfAPersonNamingTheirAuthor();

        // Then
        static::assertSame([], array_values(array_diff($named, $onThePage)));
    }

    /**
     * Decision 0022
     */
    #[Test]
    public function everyReadThePageListsNamesTheAdministratorWhoMadeIt(): void
    {
        // When
        $named = self::actsOfAPersonNamingTheirAuthor();

        // Then
        static::assertSame([], array_values(array_diff(ReadsByAnAdministrator::NAMES, $named)));
    }

    /**
     * @return list<string>
     */
    private static function actsOfAPersonNamingTheirAuthor(): array
    {
        $reflection = new ReflectionClass(TokensIssued::class);
        $file = $reflection->getFileName();
        if ($file === false) {
            static::fail('The events of the package are read from the directory of one of them.');
        }
        $files = glob(dirname($file) . '/*.php');
        if ($files === false) {
            static::fail(sprintf('The directory of the events cannot be read: %s.', dirname($file)));
        }
        $named = [];
        foreach ($files as $candidate) {
            /** @var class-string $class */
            $class = $reflection->getNamespaceName() . '\\' . basename($candidate, '.php');
            if (! class_exists($class) || ! is_a($class, NamesItsAuthorInterface::class, true) || ! is_a($class, ConcernsAPersonInterface::class, true)) {
                continue;
            }
            $name = new ReflectionClass($class)->getConstant('NAME');
            static::assertIsString($name, sprintf('The act "%s" gives itself no name.', $class));
            $named[] = $name;
        }
        sort($named);

        return $named;
    }
}
