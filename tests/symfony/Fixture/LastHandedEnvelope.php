<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Middleware\MiddlewareInterface;
use Symfony\Component\Messenger\Middleware\StackInterface;

/**
 * The envelope a bus hands its handlers, as the stamps of a worker leave it.
 */
final class LastHandedEnvelope implements MiddlewareInterface
{
    public ?Envelope $envelope = null;

    public function handle(Envelope $envelope, StackInterface $stack): Envelope
    {
        $this->envelope = $envelope;

        return $stack->next()->handle($envelope, $stack);
    }
}
