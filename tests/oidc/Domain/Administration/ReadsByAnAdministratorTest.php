<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Administration;

use function array_diff;
use function array_keys;
use function array_values;
use function basename;
use function array_fill_keys;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Oidc\Domain\Administration\ReadsByAnAdministrator;
use Beffroi\Oidc\Domain\Consent\ConsentActs;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Beffroi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use Beffroi\Oidc\Domain\Event\ReadRefusedToAnAdministrator;
use Beffroi\Oidc\Domain\Event\RefreshTokenOutlivedItsSession;
use Beffroi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Beffroi\Oidc\Domain\Event\RefreshTokenRotated;
use Beffroi\Oidc\Domain\Event\UserInfoAnswered;
use Beffroi\Oidc\Domain\Event\LogoutTokenGivenUp;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Domain\Event\TokenRevoked;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Tests\Domain\Event\EventsLeaveTheProcessTest;
use function class_exists;
use function dirname;
use function glob;
use function in_array;
use function ksort;
use function is_a;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function sort;
use function sprintf;

final class ReadsByAnAdministratorTest extends TestCase
{
    /**
     * The acts of a person that the page of their acts does not list, each with the reason: their archive holds them,
     * saying who did it.
     */
    private const array OFF_THE_PAGE = [
        LogoutTokenIssued::NAME => 'an application told of a session the administrator ended, which no page of the person lists whoever ended it',
        LogoutTokenGivenUp::NAME => 'the same telling given up',
        TokenRevoked::NAME => 'a token an application took back of itself (RFC 7009), which no page of the person lists',
        AuthorizationCodeIssued::NAME => self::BY_APPLICATION,
        AuthorizationCodeReplayed::NAME => self::BY_APPLICATION,
        BackchannelRequestAnswered::NAME => self::BY_APPLICATION,
        IntrospectionAnswered::NAME => self::BY_APPLICATION,
        RefreshTokenOutlivedItsSession::NAME => self::BY_APPLICATION,
        RefreshTokenReuseDetected::NAME => self::BY_APPLICATION,
        RefreshTokenRotated::NAME => self::BY_APPLICATION,
        TokensIssued::NAME => self::BY_APPLICATION,
        UserInfoAnswered::NAME => self::BY_APPLICATION,
        ReadRefusedToAnAdministrator::NAME => 'a read the budget of an administrator refused them, which delivered nobody',
    ];

    private const string BY_APPLICATION = 'an act of the protocol, which the person reads application by application';

    /**
     * Decisions 0022 and 0038: the person reads on the page of their acts what was done to them, an administrator's
     * reads and changes included. An act of the tenant alone, an initial access token or a client, is on no page of a
     * person.
     */
    #[Test]
    public function everyActOfAPersonIsOnTheirPageOrIsNamedAsOffIt(): void
    {
        // Given
        $onThePage = [...ReadsByAnAdministrator::NAMES, ...ConsentActs::NAMES, ...array_keys(self::OFF_THE_PAGE)];

        // When
        $named = self::actsOfAPerson();

        // Then
        static::assertSame([], array_values(array_diff($named, $onThePage)));
    }

    /**
     * Decisions 0022 and 0066
     */
    #[Test]
    public function everyReadThePageListsNamesTheAdministratorWhoMadeIt(): void
    {
        // When
        $authors = [];
        foreach (EventsLeaveTheProcessTest::events() as [$event]) {
            if (in_array($event->name(), ReadsByAnAdministrator::NAMES, true)) {
                $authors[$event->name()] = $event->author()::class;
            }
        }

        // Then
        $expected = array_fill_keys(ReadsByAnAdministrator::NAMES, AnAdministrator::class);
        ksort($expected);
        ksort($authors);
        static::assertSame($expected, $authors);
    }

    /**
     * Decisions 0022 and 0038: what an administrator did to a person is on the page of their acts, and none of it is
     * named off the page. A read an administrator made of themselves is their own.
     */
    #[Test]
    public function noActAnAdministratorDidToAPersonIsNamedOffTheirPage(): void
    {
        // Given
        $onThePage = [...ReadsByAnAdministrator::NAMES, ...ConsentActs::NAMES];

        // When
        $offThePage = [];
        foreach (EventsLeaveTheProcessTest::events() as [$event]) {
            $author = $event->author();
            if (
                $event instanceof ConcernsAPersonInterface
                && $author instanceof AnAdministrator
                && $event->subject()?->equals($author->subject) !== true
                && ! in_array($event->name(), $onThePage, true)
            ) {
                $offThePage[] = $event->name();
            }
        }

        // Then
        static::assertSame([], $offThePage);
    }

    /**
     * @return list<string>
     */
    private static function actsOfAPerson(): array
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
            if (! class_exists($class) || ! is_a($class, ConcernsAPersonInterface::class, true)) {
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
