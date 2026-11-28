<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Messenger\MessengerContract;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\MessageSealingAlgorithmsInterface;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Closure;
use Doctrine\DBAL\Connection;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Messenger\Transport\InMemory\InMemoryTransport;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Symfony\Component\Uid\Uuid;

final class AnActReadFromALaneIsWrittenWholeTest extends DatabaseTestCase
{
    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $cacheDir = self::getContainer()->getParameter('kernel.cache_dir');
        static::assertIsString($cacheDir);
        $this->directory = $cacheDir . '/keys';
        new Filesystem()->remove($this->directory);
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)
            ->rotate(
                self::tenant(),
                self::service('test.beffroi.message_sealing_algorithms', MessageSealingAlgorithmsInterface::class)->defaultAlgorithm(),
                self::context(),
            );
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        new Filesystem()->remove($this->directory);
    }

    /**
     * Decision 0062
     *
     * @param Closure(DateTimeImmutable, Tenant, RequestContext): DomainEventInterface $refusal
     * @param array{string, string|null}                                              $written
     */
    #[Test]
    #[DataProvider('provideRefusals')]
    public function aRefusalReadFromALaneKeepsItsReasonAndItsMethod(Closure $refusal, array $written): void
    {
        // Given
        $lane = new InMemoryTransport(self::service('test.beffroi.messenger_serializer', SerializerInterface::class));
        $event = $refusal(self::now(), self::tenant(), self::context());
        $lane->send(new Envelope($event));
        self::reload();

        // When
        foreach ($lane->get() as $envelope) {
            self::service('event.bus', MessageBusInterface::class)
                ->dispatch($envelope->with(new ReceivedStamp(MessengerContract::routing()[DomainEventInterface::class])));
        }
        self::reload();

        // Then
        $act = self::onlyActNamed($event->name());
        static::assertSame($written, [$act->reason, $act->method]);
    }

    /**
     * @return iterable<string, array{Closure(DateTimeImmutable, Tenant, RequestContext): DomainEventInterface, array{string, string|null}}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'a client that failed to authenticate' => [
            static fn (DateTimeImmutable $now, Tenant $tenant, RequestContext $context): DomainEventInterface => new ClientAuthenticationFailed(
                $now,
                $tenant,
                $context,
                ClientAuthenticationFailureReason::InvalidSecret,
                'oidc-demo',
                'client_secret_basic',
            ),
            ['invalid_secret', 'client_secret_basic'],
        ];
        yield 'a person who failed to authenticate' => [
            static fn (DateTimeImmutable $now, Tenant $tenant, RequestContext $context): DomainEventInterface => new AuthenticationFailed(
                $now,
                $tenant,
                $context,
                AuthenticationMethod::password(),
                AuthenticationFailureReason::InvalidCredential,
                null,
                null,
            ),
            ['invalid_credential', 'pwd'],
        ];
    }

    private static function onlyActNamed(string $name): JournalEntry
    {
        $ids = self::service('doctrine.dbal.default_connection', Connection::class)->fetchFirstColumn('SELECT id FROM beffroi_journal WHERE act = ?', [$name]);
        static::assertCount(1, $ids);
        static::assertIsString($ids[0]);

        return self::entityManager()->find(JournalEntry::class, Uuid::fromString($ids[0])) ?? static::fail('The act was not written down.');
    }
}
