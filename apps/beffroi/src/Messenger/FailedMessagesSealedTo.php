<?php

declare(strict_types=1);

namespace App\Messenger;

use Beffroi\Core\Bridge\JwtLibrary\SealedMessageBody;
use Beffroi\Core\Domain\Key\MessageSealingAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\RetirementHoldInterface;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception as DbalException;
use function is_array;
use function is_string;
use function json_decode;
use function sprintf;

/**
 * Decision 0020
 *
 * A message nobody replays or removes waits in the failure transport for as long as an operator leaves it, which no
 * retirement window can count: the message keys its body and its stamps are sealed to wait with it.
 */
final readonly class FailedMessagesSealedTo implements RetirementHoldInterface
{
    public function __construct(
        private Connection $connection,
    ) {
    }

    public function holds(TenantKey $key): bool
    {
        if (! $key->algorithm instanceof MessageSealingAlgorithmInterface) {
            return false;
        }
        try {
            // A migration creates the table: a database no migration built, as a suite's, holds none.
            if (! $this->connection->createSchemaManager()->tablesExist([MessengerContract::FAILURE_TABLE])) {
                return false;
            }
            $rows = $this->connection->iterateAssociative(
                sprintf('SELECT body, headers FROM %s WHERE queue_name = ?', MessengerContract::FAILURE_TABLE),
                [MessengerContract::FAILURE_TRANSPORT],
            );
            foreach ($rows as $row) {
                foreach ([$row['body'] ?? null, ...self::sealedStampsOf($row['headers'] ?? null)] as $sealed) {
                    if (is_string($sealed) && SealedMessageBody::keyOf($key->tenant, $sealed) === $key->kid) {
                        return true;
                    }
                }
            }
        } catch (DbalException $exception) {
            throw new RuntimeException('The failure transport cannot be read: whether a message waiting there is sealed to the key is unknown.', 0, $exception);
        }

        return false;
    }

    /**
     * The headers as the Doctrine transport stores them, a JSON object.
     *
     * @return list<string>
     */
    private static function sealedStampsOf(mixed $headers): array
    {
        if (! is_string($headers)) {
            return [];
        }
        $decoded = json_decode($headers, true);

        return is_array($decoded) ? SealedBodySerializer::sealedStampsIn($decoded) : [];
    }

    public function name(): string
    {
        return 'a message waiting in the failure transport, which "messenger:failed:retry" replays and "messenger:failed:remove" removes';
    }
}
