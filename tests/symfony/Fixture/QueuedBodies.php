<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Doctrine\DBAL\Connection;
use Doctrine\Persistence\ConnectionRegistry;
use stdClass;
use Symfony\Component\Messenger\Bridge\Doctrine\Transport\DoctrineTransportFactory;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Symfony\Component\Messenger\Transport\SetupableTransportInterface;

/**
 * A sealed body and its headers written to a Doctrine transport of a database a test holds, as Messenger writes them.
 */
final readonly class QueuedBodies
{
    /**
     * @param array<string, string> $headers
     */
    public static function send(Connection $connection, string $dsn, string $sealedBody, array $headers = []): void
    {
        $transport = new DoctrineTransportFactory(self::registryOf($connection))->createTransport($dsn, [], self::serializerOf($sealedBody, $headers));
        if ($transport instanceof SetupableTransportInterface) {
            $transport->setup();
        }
        $transport->send(new Envelope(new stdClass()));
    }

    private static function registryOf(Connection $connection): ConnectionRegistry
    {
        return new readonly class($connection) implements ConnectionRegistry {
            public function __construct(
                private Connection $connection,
            ) {
            }

            public function getDefaultConnectionName(): string
            {
                return 'default';
            }

            public function getConnection(?string $name = null): object
            {
                return $this->connection;
            }

            public function getConnections(): array
            {
                return ['default' => $this->connection];
            }

            public function getConnectionNames(): array
            {
                return ['default' => 'default'];
            }
        };
    }

    /**
     * @param array<string, string> $headers
     */
    private static function serializerOf(string $sealedBody, array $headers): SerializerInterface
    {
        return new readonly class($sealedBody, $headers) implements SerializerInterface {
            /**
             * @param array<string, string> $headers
             */
            public function __construct(
                private string $sealedBody,
                private array $headers,
            ) {
            }

            public function decode(array $encodedEnvelope): Envelope
            {
                return new Envelope(new stdClass());
            }

            public function encode(Envelope $envelope): array
            {
                return [
                    'body' => $this->sealedBody,
                    'headers' => $this->headers,
                ];
            }
        };
    }
}
