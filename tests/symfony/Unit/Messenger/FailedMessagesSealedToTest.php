<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use App\Messenger\FailedMessagesSealedTo;
use App\Messenger\LaneDsn;
use App\Messenger\MessengerContract;
use App\Messenger\SealedBodySerializer;
use App\Messenger\SealedStamps;
use App\Tests\Symfony\Fixture\QueuedBodies;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function base64_encode;
use function serialize;
use function str_replace;

/**
 * Decision 0020
 */
final class FailedMessagesSealedToTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private Connection $connection;

    private TenantKey $messageKey;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ]);
        $this->messageKey = $this->key(Algorithms::messageSeal(), Keys::messagePair());
    }

    #[Test]
    public function aMessageKeyABodyOfTheFailureTransportIsSealedToIsHeld(): void
    {
        // Given
        $this->sendTo(MessengerContract::FAILURE_DSN, $this->sealed());

        // When / Then
        static::assertTrue(new FailedMessagesSealedTo($this->connection)->holds($this->messageKey));
    }

    #[Test]
    public function aMessageKeyTheSealedStampsOfAFailedMessageAreSealedToIsHeld(): void
    {
        // Given
        $this->sendTo(MessengerContract::FAILURE_DSN, 'a body sealed to a key this tenant no longer holds', [
            SealedBodySerializer::STAMP_HEADER_PREFIX . SealedStamps::class => base64_encode(serialize([new SealedStamps($this->sealed())])),
        ]);

        // When / Then
        static::assertTrue(new FailedMessagesSealedTo($this->connection)->holds($this->messageKey));
    }

    #[Test]
    public function aMessageKeyNoFailedBodyIsSealedToIsNotHeld(): void
    {
        // Given
        $this->sendTo(MessengerContract::FAILURE_DSN, $this->sealed());
        $other = $this->key(Algorithms::messageSeal(), Keys::otherMessagePair());

        // When / Then
        static::assertFalse(new FailedMessagesSealedTo($this->connection)->holds($other));
    }

    #[Test]
    public function aBodyWaitingInALaneHoldsNothing(): void
    {
        // Given
        $this->sendTo(str_replace(LaneDsn::PLACEHOLDER, 'async_priority_low', MessengerContract::DEFAULT_DSN), $this->sealed());

        // When / Then
        static::assertFalse(new FailedMessagesSealedTo($this->connection)->holds($this->messageKey));
    }

    #[Test]
    public function aKeyThatSealsNoMessageIsNeverHeldWhateverItsKid(): void
    {
        // Given
        $this->sendTo(MessengerContract::FAILURE_DSN, $this->sealed());
        $signing = new TenantKey(
            $this->messageKey->kid,
            $this->tenant,
            Algorithms::rs256(),
            [
                ...Keys::pair()->publicJwk,
                'kid' => $this->messageKey->kid,
            ],
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );

        // When / Then
        static::assertFalse(new FailedMessagesSealedTo($this->connection)->holds($signing));
    }

    #[Test]
    public function aDatabaseWhoseFailureTransportHoldsNothingYetHoldsNoKey(): void
    {
        // When / Then
        static::assertFalse(new FailedMessagesSealedTo($this->connection)->holds($this->messageKey));
    }

    private function sealed(): string
    {
        return new JwtLibraryMessageBodySealer(new SealedKeyProvider($this->keys, Keys::opened()), Algorithms::messageSealing())->seal($this->tenant, 'a:0:{}');
    }

    /**
     * @param array<string, string> $headers
     */
    private function sendTo(string $dsn, string $body, array $headers = []): void
    {
        QueuedBodies::send($this->connection, $dsn, $body, $headers);
    }

    private function key(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
