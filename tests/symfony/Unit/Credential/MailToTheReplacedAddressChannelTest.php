<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use function array_map;
use App\Credential\MailToTheReplacedAddressChannel;
use App\Mail\MailSender;
use App\Messenger\NotificationNotDeliveredException;
use App\Tests\Symfony\Fixture\CatalogueNotices;
use App\Tests\Symfony\Fixture\MailProtections;
use App\Tests\Symfony\Fixture\RecordingMailTransport;
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
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;

/**
 * Decision 0049, CNIL délibération n° 2022-100 point 55
 */
final class MailToTheReplacedAddressChannelTest extends TestCase
{
    private const string REPLACED = 'alice@acme.example';

    private const string CURRENT = 'alice@elsewhere.example';

    private RecordingMailTransport $transport;

    private User $alice;

    protected function setUp(): void
    {
        $this->transport = new RecordingMailTransport();
        $this->alice = Fixtures::user();
        $this->alice->changeEmail(new EmailAddress(self::CURRENT), true, Fixtures::now());
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55, BSI TR-03161-2 O.Auth_16
     */
    #[Test]
    public function theChangeIsWrittenToTheAddressItReplaced(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::address(new EmailAddress(self::REPLACED), null)));

        // Then
        static::assertSame([self::REPLACED], array_map(static fn (Address $address): string => $address->getAddress(), $this->transport->sent[0]->getTo()));
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theMailNamesTheChannelAndNeitherItsValueBeforeNorAfter(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::address(new EmailAddress(self::REPLACED), null)));

        // Then
        static::assertSame(
            "The email address of your account was changed on 22 Nov 2026, 14:05 UTC. If it was not you, open your account.\n\nhttps://id.acme.example/account\n",
            $this->transport->sent[0]->getTextBody(),
        );
    }

    /**
     * Decision 0049: a number is plain text, and may be written as an address is.
     */
    #[Test]
    public function aChangeThatReplacedANumberIsWrittenToNoAddressEvenOneItSpells(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::number(self::REPLACED)));

        // Then
        static::assertSame([], $this->transport->sent);
    }

    /**
     * Decision 0048, decision 0049
     */
    #[Test]
    public function aChangeThatReplacedNothingVerifiedIsWrittenToNoAddress(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change(null));

        // Then
        static::assertSame([], $this->transport->sent);
    }

    /**
     * Decision 0049, Architecture §5.6
     */
    #[Test]
    public function aMailTheTransportDidNotTakeBringsTheNoticeBack(): void
    {
        // Given
        $this->transport = new RecordingMailTransport(refusing: true);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);

        // When
        $this->channel()->tell($this->alice, $this->change(ReplacedChannel::address(new EmailAddress(self::REPLACED), null)));
    }

    private function channel(): MailToTheReplacedAddressChannel
    {
        return new MailToTheReplacedAddressChannel(
            CatalogueNotices::create(),
            new MailSender(fn (): TransportInterface => $this->transport, 'no-reply@acme.example', MailProtections::plain(), new NullLogger()),
        );
    }

    private function change(?ReplacedChannel $replaced): CredentialChange
    {
        return new CredentialChange(
            $this->alice,
            ChannelChangeNotice::ACT,
            new DateTimeImmutable('2026-11-22T14:05:00+00:00'),
            $replaced->claim ?? 'email',
            $replaced,
        );
    }
}
