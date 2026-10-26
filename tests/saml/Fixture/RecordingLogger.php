<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Psr\Log\AbstractLogger;
use Stringable;

/**
 * What was written to the log, level, message and context, for a test to read.
 */
final class RecordingLogger extends AbstractLogger
{
    /**
     * @var list<array{level: mixed, message: string, context: array<array-key, mixed>}>
     */
    public private(set) array $records = [];

    /**
     * @param array<array-key, mixed> $context
     */
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => $level,
            'message' => (string) $message,
            'context' => $context,
        ];
    }
}
