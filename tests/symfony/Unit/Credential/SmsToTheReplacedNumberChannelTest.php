<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use function array_map;
use App\Credential\SmsToTheReplacedNumberChannel;
use App\Messenger\NotificationNotDeliveredException;
use App\Sms\SmsSender;
use App\Tests\Symfony\Fixture\CatalogueNotices;
use App\Tests\Symfony\Fixture\RecordingSmsTransport;
use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Notifier\Message\SmsMessage;
use Symfony\Component\Notifier\Transport\TransportInterface;

/**
 * Decision 0049, CNIL délibération n° 2022-100 point 55
 */
final class SmsToTheReplacedNumberChannelTest extends TestCase
{
    private const string REPLACED = '+44 1865 000000';

    private const string CURRENT = '+44 1865 999999';

    private RecordingSmsTransport $transport;

    private User $alice;

    protected function setUp(): void
    {
        $this->transport = new RecordingSmsTransport();
        $this->alice = Fixtures::user();
        $this->alice->changePhoneNumber(self::CURRENT, true, Fixtures::now());
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55, BSI TR-03161-2 O.Auth_16
     */
    #[Test]
    public function theChangeIsTextedToTheNumberItReplaced(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::number(self::REPLACED)));

        // Then
        static::assertSame([self::REPLACED], array_map(static fn (SmsMessage $text): string => $text->getPhone(), $this->transport->sent));
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theTextNamesTheChannelAndNeitherItsValueBeforeNorAfter(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::number(self::REPLACED)));

        // Then
        static::assertSame(
            "Acme\nThe phone number of your account was changed on 22 Nov 2026, 14:05 UTC. If it was not you, open your account.\nhttps://id.acme.example/account",
            $this->transport->sent[0]->getSubject(),
        );
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aChangeThatReplacedAnAddressIsTextedToNoNumber(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::address(new EmailAddress('alice@acme.example'), null)));

        // Then
        static::assertSame([], $this->transport->sent);
    }

    /**
     * Decision 0049, Architecture §5.6
     */
    #[Test]
    public function aTextTheTransportDidNotTakeBringsTheNoticeBack(): void
    {
        // Given
        $this->transport = new RecordingSmsTransport(refusing: true);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);

        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::number(self::REPLACED)));
    }

    private function channel(): SmsToTheReplacedNumberChannel
    {
        return new SmsToTheReplacedNumberChannel(
            CatalogueNotices::create(),
            new SmsSender(fn (): TransportInterface => $this->transport, new NullLogger()),
        );
    }

    private function change(ReplacedChannel $replaced): CredentialChange
    {
        return new CredentialChange($this->alice, ChannelChangeNotice::ACT, new DateTimeImmutable('2026-11-22T14:05:00+00:00'), $replaced->claim, $replaced);
    }
}
