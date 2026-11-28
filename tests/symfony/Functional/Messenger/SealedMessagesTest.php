<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Messenger;

use function array_map;
use App\Message\AdvanceKeyLifecycle;
use App\Message\CheckThePasswordAgainstTheBreaches;
use App\Messenger\MessengerContract;
use App\Messenger\SealedBodySerializer;
use App\Messenger\TenantStamp;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Fixture\LastHandedEnvelope;
use App\Tests\Symfony\Fixture\SomethingHappened;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Domain\Event\TenantKeyStaged;
use Beffroi\Core\Port\MessageSealingAlgorithmsInterface;
use Beffroi\Core\Port\PublicKeySetProviderInterface;
use function base64_decode;
use function base64_encode;
use Closure;
use function explode;
use function implode;
use function is_scalar;
use function json_decode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function serialize;
use function sprintf;
use function substr_replace;
use Symfony\Component\Messenger\Bridge\Doctrine\Transport\DoctrineTransport;
use Symfony\Component\Messenger\Bridge\Doctrine\Transport\DoctrineTransportFactory;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\Command\FailedMessagesShowCommand;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\EventListener\AddErrorDetailsStampListener;
use Symfony\Component\Messenger\EventListener\SendFailedMessageForRetryListener;
use Symfony\Component\Messenger\EventListener\SendFailedMessageToFailureTransportListener;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\Exception\UnrecoverableMessageHandlingException;
use Symfony\Component\Messenger\Handler\HandlersLocator;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Middleware\DecodeFailedMessageMiddleware;
use Symfony\Component\Messenger\Middleware\HandleMessageMiddleware;
use Symfony\Component\Messenger\Retry\MultiplierRetryStrategy;
use Symfony\Component\Messenger\Retry\RetryStrategyInterface;
use Symfony\Component\Messenger\Stamp\ErrorDetailsStamp;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Symfony\Component\Messenger\Transport\TransportInterface;
use Symfony\Component\Messenger\Worker;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0020
 */
final class SealedMessagesTest extends DatabaseTestCase
{
    private const string LANE = 'async_priority_low';

    private const string LANE_DSN = 'doctrine://default?queue_name=' . self::LANE;

    private const string ADDRESS = 'bob.martin@example.org';

    private const string REFUSAL = 'The relay refused the recipient ' . self::ADDRESS . '.';

    private string $directory;

    private SerializerInterface $serializer;

    protected function setUp(): void
    {
        parent::setUp();
        $cacheDir = self::getContainer()->getParameter('kernel.cache_dir');
        static::assertIsString($cacheDir);
        $this->directory = $cacheDir . '/keys';
        new Filesystem()->remove($this->directory);
        $this->serializer = self::service('test.beffroi.messenger_serializer', SerializerInterface::class);
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

    #[Test]
    public function everyTransportEncodesWithTheSerializerOfTheProvider(): void
    {
        // When / Then
        static::assertInstanceOf(SealedBodySerializer::class, $this->serializer);
    }

    #[Test]
    public function theFirstMessageKeyOfATenantSealsTheEventThatAnnouncesIt(): void
    {
        // Given
        new Filesystem()->remove($this->directory);
        $staged = self::service('test.beffroi.key_staging', KeyStaging::class)
            ->stage(
                self::tenant(),
                self::service('test.beffroi.message_sealing_algorithms', MessageSealingAlgorithmsInterface::class)->defaultAlgorithm(),
                self::context(),
            );

        // When
        $encoded = $this->serializer->encode(new Envelope(new TenantKeyStaged($staged, self::now(), self::context())));

        // Then
        static::assertTrue($staged->isStaged());
        static::assertCount(5, explode('.', $encoded['body']));
        static::assertSame(TenantKeyStaged::class, $encoded['headers'][SealedBodySerializer::TYPE_HEADER] ?? null);
    }

    #[Test]
    public function aMessageIsSealedToTheKeyOfTheTenantAndOpensBack(): void
    {
        // Given
        $message = new KmsUnavailable(self::now(), self::tenant(), self::context(), 'the vault did not answer');

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertCount(5, explode('.', $encoded['body']));
        static::assertSame(serialize($message), serialize($this->serializer->decode($encoded)->getMessage()));
    }

    #[Test]
    #[DataProvider('provideWhatTheMessageCarries')]
    public function theEncodedBodyGivesNoneOfTheValuesTheMessageCarriedAway(string $value): void
    {
        // Given
        $message = new KmsUnavailable(self::now(), self::tenant(), self::context(), 'the vault did not answer');

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertStringContainsString($value, serialize($message));
        static::assertStringNotContainsString($value, $encoded['body']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatTheMessageCarries(): iterable
    {
        yield 'the address of the request' => [SealedRows::IP_ADDRESS];
        yield 'the user agent of the request' => [SealedRows::USER_AGENT];
        yield 'what the provider had to say' => ['the vault did not answer'];
    }

    #[Test]
    public function theDigestOfAPasswordLeavesSealed(): void
    {
        // Given
        $digest = PasswordDigest::of('correct horse battery staple');
        $message = new CheckThePasswordAgainstTheBreaches(Uuid::v7(), $digest->value);

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertStringContainsString($digest->value, serialize($message));
        static::assertStringNotContainsString($digest->value, $encoded['body']);
    }

    #[Test]
    public function theHeadersNameTheClassAndTheScopeAndNothingElse(): void
    {
        // When
        $encoded = $this->serializer->encode(new Envelope(new AdvanceKeyLifecycle()));

        // Then
        static::assertSame(
            [
                SealedBodySerializer::TYPE_HEADER => AdvanceKeyLifecycle::class,
                SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class => base64_encode(serialize([
                    new TenantStamp(self::tenant()->slug),
                ])),
            ],
            $encoded['headers'] ?? [],
        );
    }

    #[Test]
    public function theKeyAMessageIsSealedToIsNotPublished(): void
    {
        // Given
        $sealing = self::service('test.beffroi.message_sealing_algorithms', MessageSealingAlgorithmsInterface::class)->defaultAlgorithm()->name();

        // When
        $published = self::service('test.beffroi.public_keys', PublicKeySetProviderInterface::class)->publicKeys(self::tenant());

        // Then
        foreach ($published->keys as $key) {
            static::assertNotSame($sealing, $key->algorithm->name());
        }
    }

    #[Test]
    public function theFailureTransportHoldsNoHeaderFromWhichTheErrorOfAHandlerCanBeRead(): void
    {
        // Given
        self::aHandlerFailedNamingAnAddress();

        // When
        $row = self::theFailedRow();

        // Then
        static::assertStringNotContainsString(self::ADDRESS, $row['body']);
        foreach ($row['headers'] as $name => $header) {
            static::assertStringNotContainsString(self::ADDRESS, $header, sprintf('the header "%s" gives the address away.', $name));
            static::assertStringNotContainsString(
                self::ADDRESS,
                (string) base64_decode($header, true),
                sprintf('the header "%s" gives the address away.', $name),
            );
        }
    }

    #[Test]
    public function theErrorOfAHandlerReadsBackFromTheFailureTransport(): void
    {
        // Given
        $failure = self::aHandlerFailedNamingAnAddress();

        // When
        $failed = [...$failure->all()];

        // Then
        static::assertCount(1, $failed);
        static::assertSame(self::REFUSAL, $failed[0]->last(ErrorDetailsStamp::class)?->getExceptionMessage());
    }

    #[Test]
    public function messengerFailedShowShowsTheErrorOfAHandler(): void
    {
        // Given
        $failure = self::aHandlerFailedNamingAnAddress();
        $show = new CommandTester(new FailedMessagesShowCommand(
            MessengerContract::FAILURE_TRANSPORT,
            new ServiceLocator([MessengerContract::FAILURE_TRANSPORT => static fn (): TransportInterface => $failure]),
        ));

        // When
        $show->execute([
            'id' => self::theFailedRow()['id'],
        ]);

        // Then
        static::assertStringContainsString(self::REFUSAL, $show->getDisplay());
    }

    #[Test]
    public function aMessageReplayedFromTheFailureTransportReachesItsHandlerWithTheErrorOfItsFailure(): void
    {
        // Given
        $failure = self::aHandlerFailedNamingAnAddress();
        $handed = new LastHandedEnvelope();

        // When
        self::work(MessengerContract::FAILURE_TRANSPORT, $failure, $failure, self::busOf(static function (SomethingHappened $message): void {
        }, $handed));

        // Then
        static::assertSame(self::REFUSAL, $handed->envelope?->last(ErrorDetailsStamp::class)?->getExceptionMessage());
    }

    #[Test]
    public function aBodyThatDoesNotOpenIsCountedAndSentToTheFailureTransport(): void
    {
        // Given
        $lane = self::transport(self::LANE_DSN);
        $failure = self::transport(MessengerContract::FAILURE_DSN);
        $lane->send(new Envelope(new SomethingHappened('a page was rendered')));
        self::tamperWithTheBodiesOf(self::LANE);

        // When
        self::work(self::LANE, $lane, $failure, self::busOf(static function (SomethingHappened $message): void {
        }, new LastHandedEnvelope()));

        // Then
        $failed = [...$failure->all()];
        static::assertCount(1, $failed);
        static::assertInstanceOf(MessageDecodingFailedException::class, $failed[0]->getMessage());
        static::assertSame([1, 0], array_map(
            static fn (RedeliveryStamp $stamp): int => $stamp->getRetryCount(),
            $failed[0]->all(RedeliveryStamp::class),
        ));
    }

    #[Test]
    public function theFailureTransportIsNotAnExceptionToTheSealing(): void
    {
        // Given
        $configuration = MessengerContract::configuration();
        $serializer = $configuration['serializer'];
        $transports = $configuration['transports'];

        // When / Then
        static::assertIsArray($serializer);
        static::assertSame(MessengerContract::SERIALIZER, $serializer['default_serializer'] ?? null);
        static::assertIsArray($transports);
        static::assertArrayNotHasKey('serializer', (array) ($transports[MessengerContract::FAILURE_TRANSPORT] ?? []));
    }

    /**
     * A handler of a lane refuses its message for good, naming an address, as a mail relay names the recipient it
     * refuses; the worker sends the message to the failure transport.
     */
    private static function aHandlerFailedNamingAnAddress(): DoctrineTransport
    {
        $lane = self::transport(self::LANE_DSN);
        $failure = self::transport(MessengerContract::FAILURE_DSN);
        $lane->send(new Envelope(new SomethingHappened('a page was rendered')));
        self::work(self::LANE, $lane, $failure, self::busOf(static function (SomethingHappened $message): never {
            throw new UnrecoverableMessageHandlingException(self::REFUSAL);
        }, new LastHandedEnvelope()));

        return $failure;
    }

    private static function transport(string $dsn): DoctrineTransport
    {
        $transport = new DoctrineTransportFactory(self::registry())->createTransport(
            $dsn,
            [],
            self::service('test.beffroi.messenger_serializer', SerializerInterface::class),
        );
        static::assertInstanceOf(DoctrineTransport::class, $transport);
        $transport->setup();

        return $transport;
    }

    /**
     * The bus as a worker hands it a message: a body that did not decode decoded again, then the handler.
     */
    private static function busOf(Closure $handler, LastHandedEnvelope $handed): MessageBus
    {
        $serializer = self::service('test.beffroi.messenger_serializer', SerializerInterface::class);

        return new MessageBus([
            new DecodeFailedMessageMiddleware(new ServiceLocator([
                self::LANE => static fn (): SerializerInterface => $serializer,
                MessengerContract::FAILURE_TRANSPORT => static fn (): SerializerInterface => $serializer,
            ])),
            $handed,
            new HandleMessageMiddleware(new HandlersLocator([
                SomethingHappened::class => [$handler],
            ])),
        ]);
    }

    /**
     * The listeners a worker of the component runs: the error details added, a failure retried once without waiting,
     * then sent to the failure transport; the worker stops once its transport is empty.
     */
    private static function work(string $name, TransportInterface $receiver, TransportInterface $failure, MessageBusInterface $bus): void
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new AddErrorDetailsStampListener());
        $dispatcher->addSubscriber(new SendFailedMessageForRetryListener(
            new ServiceLocator([$name => static fn (): TransportInterface => $receiver]),
            new ServiceLocator([$name => static fn (): RetryStrategyInterface => new MultiplierRetryStrategy(1, 0, 1, 0, 0)]),
        ));
        $dispatcher->addSubscriber(new SendFailedMessageToFailureTransportListener(
            new ServiceLocator([$name => static fn (): TransportInterface => $failure]),
        ));
        new Worker([$name => $receiver], $bus, $dispatcher)->run([
            'sleep' => 0,
            'stop_when_empty' => true,
        ]);
    }

    /**
     * @return array{id: string, body: string, headers: array<string, string>}
     */
    private static function theFailedRow(): array
    {
        $rows = self::entityManager()
            ->getConnection()
            ->fetchAllAssociative(
                sprintf('SELECT id, body, headers FROM %s WHERE queue_name = ?', MessengerContract::FAILURE_TABLE),
                [MessengerContract::FAILURE_TRANSPORT],
            );
        static::assertCount(1, $rows);
        static::assertIsString($rows[0]['body']);
        static::assertIsString($rows[0]['headers']);
        $headers = json_decode($rows[0]['headers'], true);
        static::assertIsArray($headers);
        $read = [];
        foreach ($headers as $name => $header) {
            static::assertIsString($name);
            static::assertIsString($header);
            $read[$name] = $header;
        }

        return [
            'id' => is_scalar($rows[0]['id']) ? (string) $rows[0]['id'] : '',
            'body' => $rows[0]['body'],
            'headers' => $read,
        ];
    }

    private static function tamperWithTheBodiesOf(string $queue): void
    {
        $connection = self::entityManager()->getConnection();
        $body = $connection->fetchOne(sprintf('SELECT body FROM %s WHERE queue_name = ?', MessengerContract::FAILURE_TABLE), [$queue]);
        static::assertIsString($body);
        $parts = explode('.', $body);
        $parts[3] = substr_replace($parts[3], $parts[3][8] === 'A' ? 'B' : 'A', 8, 1);
        $connection->executeStatement(
            sprintf('UPDATE %s SET body = ? WHERE queue_name = ?', MessengerContract::FAILURE_TABLE),
            [implode('.', $parts), $queue],
        );
    }
}
