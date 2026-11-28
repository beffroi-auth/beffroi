<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ThePerson;
use PHPUnit\Framework\Assert;
use function preg_quote;
use function preg_replace;
use function serialize;
use function sprintf;
use function strlen;

/**
 * What a queue holds of an event or a message the version before acts named the kind of their author wrote: the same
 * bytes, but for its last property, `administrator`, the subject of an administrator or null where `author` is now.
 */
final readonly class BodyOfTheVersionBefore
{
    /**
     * The event or message, written with an administrator or a person for author, whom the version before named by the
     * subject of their account or by nothing.
     */
    public static function of(object $written): string
    {
        $body = serialize($written);
        $author = self::authorOf($written);
        $was = $author instanceof AnAdministrator ? serialize($author->subject) : 'N;';
        $before = preg_replace(
            '/s:6:"author";' . preg_quote(serialize($author), '/') . '/',
            sprintf('s:%d:"administrator";%s', strlen('administrator'), $was),
            $body,
            1,
            $replaced,
        );
        Assert::assertSame(1, $replaced, 'The body names its author last, as the version before named its administrator.');

        return (string) $before;
    }

    private static function authorOf(object $written): AuthorInterface
    {
        $author = (array) $written;

        return isset($author['author']) && $author['author'] instanceof AuthorInterface ? $author['author'] : new ThePerson();
    }
}
