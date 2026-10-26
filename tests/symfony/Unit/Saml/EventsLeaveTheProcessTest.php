<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use function array_map;
use function array_unique;
use function array_values;
use function basename;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\Event\ServiceProviderSignedIn;
use function class_exists;
use function glob;
use function is_a;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use function sort;
use function unserialize;

/**
 * Architecture §5.6, spec/saml.md S-26: the events of beffroi/saml are handled asynchronously, so every one of them is
 * written to a queue and read back. Here and not in the suite of the package, whose code never calls unserialize()
 * (spec/saml.md section 8): the queue is the bundle's.
 *
 * Each case is built the way the use case that raises it builds it.
 */
final class EventsLeaveTheProcessTest extends TestCase
{
    /**
     * @return iterable<string, array{DomainEventInterface}>
     */
    public static function events(): iterable
    {
        $session = Fixtures::session();

        yield 'a service provider signed in from a session' => [new ServiceProviderSignedIn(
            Fixtures::now(),
            $session->tenant,
            $session->id,
            'https://sp.example.org/saml',
            $session->user->subject,
            Fixtures::context(),
        )];
    }

    #[Test]
    #[DataProvider('events')]
    public function anEventIsWrittenToTheQueueAndReadBack(DomainEventInterface $event): void
    {
        // When
        $written = serialize($event);

        // Then
        static::assertEquals($event, unserialize($written));
    }

    /**
     * An event this test does not carry to the queue is an event nothing says a broker can take, so the cases above
     * are the events of the module and not a selection of them.
     */
    #[Test]
    public function everyEventOfTheModuleIsWrittenToTheQueue(): void
    {
        // Given
        $covered = array_values(array_unique(array_map(static fn (array $case): string => $case[0]::class, [...self::events()])));
        sort($covered);

        // When
        $files = glob(__DIR__ . '/../../../../src/saml/src/Domain/Event/*.php');
        if ($files === false) {
            static::fail('The directory of the events of beffroi/saml cannot be read.');
        }
        $declared = [];
        foreach ($files as $file) {
            $class = 'Beffroi\\Saml\\Domain\\Event\\' . basename($file, '.php');
            if (class_exists($class) && is_a($class, DomainEventInterface::class, true)) {
                $declared[] = $class;
            }
        }
        sort($declared);

        // Then
        static::assertSame($declared, $covered);
    }
}
