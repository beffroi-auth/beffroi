<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Entity\Lead;
use App\Lead\OidcProvider;
use App\Tests\DatabaseReset;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;

/**
 * The events Sweego POSTs to /webhook/sweego, signed as the Sweego bridge of the Mailer checks them: the HMAC-SHA256 of
 * "id.timestamp.body" under the secret decoded from base64, itself in base64, within five minutes of the clock.
 */
final class SweegoWebhookTest extends WebTestCase
{
    use ClockSensitiveTrait;
    use DatabaseReset;

    /** The SWEEGO_WEBHOOK_SECRET of .env.test. */
    private const string SECRET = 'tJzUPiwiPEW8/1lsUx3bhTXDl+7q2V+D';

    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        self::resetDatabase();
        self::mockTime('2026-11-26 10:35:00');
        self::entityManager()
            ->persist(new Lead(
                'lukasz@example.pl',
                'Łukasz',
                'Żółć',
                null,
                OidcProvider::Keycloak,
                null,
                'symfonycon-warsaw-2026',
                new DateTimeImmutable('2026-11-26 10:30:00'),
            ));
        self::entityManager()->flush();
        self::entityManager()->clear();
    }

    #[Test]
    public function itAcceptsASignedEvent(): void
    {
        // When
        $this->send('delivered');

        // Then
        static::assertResponseStatusCodeSame(202);
    }

    /**
     * @param callable(Lead): ?DateTimeImmutable $recorded
     */
    #[Test]
    #[DataProvider('provideRecordedEvents')]
    public function itRecordsWhatSweegoReportsOfTheConfirmation(string $eventType, callable $recorded): void
    {
        // When
        $this->send($eventType);

        // Then
        static::assertSame('2026-11-26 10:31:12', $recorded($this->lead())?->format('Y-m-d H:i:s'));
    }

    /**
     * @return iterable<string, array{string, callable(Lead): ?DateTimeImmutable}>
     */
    public static function provideRecordedEvents(): iterable
    {
        yield 'delivered' => ['delivered', static fn (Lead $lead): ?DateTimeImmutable => $lead->confirmationDeliveredAt];
        yield 'opened' => ['email_opened', static fn (Lead $lead): ?DateTimeImmutable => $lead->confirmationOpenedAt];
        yield 'clicked' => ['email_clicked', static fn (Lead $lead): ?DateTimeImmutable => $lead->confirmationClickedAt];
        yield 'a soft bounce' => ['soft-bounce', static fn (Lead $lead): ?DateTimeImmutable => $lead->confirmationBouncedAt];
        yield 'a hard bounce' => ['hard_bounce', static fn (Lead $lead): ?DateTimeImmutable => $lead->confirmationBouncedAt];
        yield 'reported as spam' => ['complaint', static fn (Lead $lead): ?DateTimeImmutable => $lead->markedAsSpamAt];
        yield 'unsubscribed' => ['list_unsub', static fn (Lead $lead): ?DateTimeImmutable => $lead->unsubscribedAt];
    }

    /**
     * Sweego took the email: the application knew it already, from the answer of its API.
     */
    #[Test]
    public function itRecordsNothingOfTheSendingItself(): void
    {
        // When
        $this->send('email_sent');

        // Then
        $lead = $this->lead();
        static::assertNull($lead->confirmationDeliveredAt);
        static::assertNull($lead->confirmationOpenedAt);
        static::assertNull($lead->confirmationClickedAt);
        static::assertNull($lead->confirmationBouncedAt);
        static::assertNull($lead->markedAsSpamAt);
        static::assertNull($lead->unsubscribedAt);
    }

    #[Test]
    public function itFindsTheLeadWhateverTheCaseOfTheRecipient(): void
    {
        // When
        $this->send('delivered', recipient: 'Lukasz@Example.PL');

        // Then
        static::assertNotNull($this->lead()->confirmationDeliveredAt);
    }

    /**
     * A lead purged, or deleted at the visitor's request: Sweego is told the event arrived, so that it stops sending it.
     */
    #[Test]
    public function itAcceptsAnEventForAnAddressNoLeadHolds(): void
    {
        // When
        $this->send('delivered', recipient: 'ada@example.com');

        // Then
        static::assertResponseStatusCodeSame(202);
    }

    #[Test]
    public function itRefusesAnEventSignedWithAnotherSecret(): void
    {
        // When
        $this->send('delivered', secret: 'R2FsbGFudCBBbm9ueW1lIFNlY3JldCBLZXk=');

        // Then
        static::assertResponseStatusCodeSame(403);
    }

    #[Test]
    public function itRecordsNothingOfAnEventSignedWithAnotherSecret(): void
    {
        // When
        $this->send('delivered', secret: 'R2FsbGFudCBBbm9ueW1lIFNlY3JldCBLZXk=');

        // Then
        static::assertNull($this->lead()->confirmationDeliveredAt);
    }

    #[Test]
    public function itRefusesAnEventSignedTooLongAgo(): void
    {
        // When
        $this->send('delivered', signedAt: '2026-11-26 10:29:59');

        // Then
        static::assertResponseStatusCodeSame(403);
    }

    /**
     * Posts an event of Sweego, shaped as the ones of its documentation, about the confirmation sent to $recipient.
     */
    private function send(
        string $eventType,
        string $recipient = 'lukasz@example.pl',
        string $secret = self::SECRET,
        string $signedAt = '2026-11-26 10:35:00',
    ): void {
        $body = json_encode(
            [
                'event_type' => $eventType,
                'timestamp' => '2026-11-26T10:31:12+00:00',
                'swg_uid' => '01-68d20f85-253e-4986-b7f0-0e4229df4d61',
                'event_id' => '9f26b9d0-13d7-410c-ba04-5019cd30e6d0',
                'channel' => 'email',
                'headers' => [
                    'x-mailer' => 'Sweego',
                    'x-transaction-id' => 'd4fbec9d-eed9-44d5-af47-c1126467a5ca',
                ],
                'campaign_type' => 'transac',
                'campaign_id' => 'transac',
                'recipient' => $recipient,
                'domain_from' => 'beffroi.tech',
            ],
            \JSON_THROW_ON_ERROR,
        );
        $id = 'msg_2pYjPrnHaKNFbQHVrnVnxZiM9Bj';
        $timestamp = (string) new DateTimeImmutable($signedAt)->getTimestamp();
        $key = base64_decode($secret, true);
        static::assertIsString($key);
        $signature = base64_encode(hash_hmac('sha256', $id . '.' . $timestamp . '.' . $body, $key, true));

        $this->client->request(
            'POST',
            '/webhook/sweego',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_WEBHOOK_ID' => $id,
                'HTTP_WEBHOOK_TIMESTAMP' => $timestamp,
                'HTTP_WEBHOOK_SIGNATURE' => $signature,
            ],
            content: $body,
        );
    }

    private function lead(): Lead
    {
        self::entityManager()->clear();
        $lead = self::entityManager()->getRepository(Lead::class)->findOneBy(['email' => 'lukasz@example.pl']);
        static::assertNotNull($lead);

        return $lead;
    }
}
