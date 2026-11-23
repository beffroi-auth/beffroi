<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Chain;

use App\Chain\LoggedCheckpointCopies;
use Beffroi\Core\Domain\Chain\Checkpoint;
use Beffroi\Core\Domain\Chain\Link;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Tests\Fixture\RecordingLogger;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Decision 0060
 */
final class LoggedCheckpointCopiesTest extends TestCase
{
    #[Test]
    public function aSignedHeadLeavesOnALineThatCarriesItWhole(): void
    {
        // Given
        $logger = new RecordingLogger();
        $tenant = Fixtures::tenant();
        $checkpoint = new Checkpoint(
            $tenant->id,
            'journal',
            new Link(7, str_repeat('a', 64)),
            Link::beforeTheFirst(),
            new Link(7, str_repeat('a', 64)),
            new DateTimeImmutable('@1789000000'),
            new DateTimeImmutable('@1789000000'),
        );

        // When
        new LoggedCheckpointCopies($logger)->copy($tenant, $checkpoint, 'the.signed.head');

        // Then
        static::assertSame(
            ['notice', 'journal', 7, 'the.signed.head'],
            [
                $logger->records[0]['level'] ?? null,
                $logger->records[0]['context']['chain'] ?? null,
                $logger->records[0]['context']['position'] ?? null,
                $logger->records[0]['context']['checkpoint'] ?? null,
            ],
        );
    }
}
