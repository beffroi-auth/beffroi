<?php

declare(strict_types=1);

namespace App\Http;

use Doctrine\DBAL\Connection;
use LogicException;
use RuntimeException;
use SensitiveParameter;
use SessionHandlerInterface;
use SessionUpdateTimestampHandlerInterface;
use function session_create_id;
use Symfony\Component\KeyManagement\EnvelopeDecrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypterInterface;

/**
 * Decision 0053: the sessions of the browsers in the database every process of a deployment shares. Each session
 * opens its rows on the connection Doctrine holds when it opens: a worker serves every request with this handler,
 * while Doctrine renews its connection once idle_connection_ttl has passed and the network drops one left idle.
 */
final class DatabaseSessions implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
{
    private ?SealedSessionRows $rows = null;

    public function __construct(
        private readonly Connection $doctrine,
        private readonly EnvelopeEncrypterInterface&EnvelopeDecrypterInterface $sealer,
    ) {
    }

    /**
     * @throws LogicException when Doctrine holds no PDO connection
     */
    public function open(string $path, string $name): bool
    {
        $this->rows = SealedSessionRows::onTheConnectionOf($this->doctrine, $this->sealer);

        return $this->rows->open($path, $name);
    }

    public function close(): bool
    {
        $rows = $this->rows;
        $this->rows = null;

        return $rows?->close() ?? true;
    }

    public function read(#[SensitiveParameter] string $id): string|false
    {
        return $this->rows()->read($id);
    }

    public function write(#[SensitiveParameter] string $id, #[SensitiveParameter] string $data): bool
    {
        return $this->rows()->write($id, $data);
    }

    public function destroy(#[SensitiveParameter] string $id): bool
    {
        return $this->rows()->destroy($id);
    }

    public function gc(int $max_lifetime): int|false
    {
        return $this->rows()->gc($max_lifetime);
    }

    /**
     * @throws RuntimeException when PHP creates no identifier
     */
    public function create_sid(): string
    {
        // Within a call of the handler, session_create_id() takes the generator of PHP, not this method.
        $id = session_create_id();
        if ($id === false) {
            throw new RuntimeException('PHP created no identifier for the session.');
        }

        return $id;
    }

    public function validateId(#[SensitiveParameter] string $id): bool
    {
        return $this->rows()->validateId($id);
    }

    public function updateTimestamp(#[SensitiveParameter] string $id, string $data): bool
    {
        return $this->rows()->updateTimestamp($id, $data);
    }

    private function rows(): SealedSessionRows
    {
        return $this->rows ??= SealedSessionRows::onTheConnectionOf($this->doctrine, $this->sealer);
    }
}
