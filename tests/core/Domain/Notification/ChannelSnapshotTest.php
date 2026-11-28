<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Notification;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChannelSnapshot;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0049
 */
final class ChannelSnapshotTest extends TestCase
{
    private const string ADDRESS = 'alice@acme.example';

    private const string NUMBER = '+44 1865 000000';

    private User $alice;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function anAddressChangedNamesTheVerifiedOneItReplaced(): void
    {
        // Given
        $this->alice->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changeEmail(new EmailAddress('alice@elsewhere.example'), false, Fixtures::now());

        // When
        $changed = $before->changedIn($this->alice);

        // Then
        static::assertEquals(['email' => ReplacedChannel::address(new EmailAddress(self::ADDRESS), null)], $changed);
    }

    /**
     * Decision 0049, decision 0051
     */
    #[Test]
    public function anAddressReplacedKeepsWhatItsMailWasEncryptedTo(): void
    {
        // Given
        $this->alice->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());
        $key = new MailEncryptionKey('pgp', 'material', 'fingerprint', [new EmailAddress(self::ADDRESS)]);
        $this->alice->encryptMailTo($key, Fixtures::now());
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changeEmail(new EmailAddress('alice@elsewhere.example'), false, Fixtures::now());

        // When
        $changed = $before->changedIn($this->alice);

        // Then
        static::assertSame($key, $changed['email']?->mailEncryption);
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function aNumberChangedNamesTheVerifiedOneItReplaced(): void
    {
        // Given
        $this->alice->changePhoneNumber(self::NUMBER, true, Fixtures::now());
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changePhoneNumber('+44 1865 999999', false, Fixtures::now());

        // When
        $changed = $before->changedIn($this->alice);

        // Then
        static::assertEquals(['phone_number' => ReplacedChannel::number(self::NUMBER)], $changed);
    }

    /**
     * Decision 0048, decision 0049
     */
    #[Test]
    public function aChannelNobodyVerifiedIsReplacedByAChangeThatReachesNothingOfIt(): void
    {
        // Given
        $this->alice->changeEmail(new EmailAddress(self::ADDRESS), false, Fixtures::now());
        $this->alice->changePhoneNumber(self::NUMBER, false, Fixtures::now());
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changeEmail(new EmailAddress('alice@elsewhere.example'), false, Fixtures::now());
        $this->alice->changePhoneNumber('+44 1865 999999', false, Fixtures::now());

        // When
        $changed = $before->changedIn($this->alice);

        // Then
        static::assertSame(['email' => null, 'phone_number' => null], $changed);
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3
     */
    #[Test]
    public function aChannelTakenAwayIsAChange(): void
    {
        // Given
        $this->alice->changePhoneNumber(self::NUMBER, true, Fixtures::now());
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changePhoneNumber(null, false, Fixtures::now());

        // When
        $changed = $before->changedIn($this->alice);

        // Then
        static::assertEquals(['phone_number' => ReplacedChannel::number(self::NUMBER)], $changed);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aVerificationAloneChangesNoChannel(): void
    {
        // Given
        $this->alice->changeEmail(new EmailAddress(self::ADDRESS), false, Fixtures::now());
        $before = ChannelSnapshot::of($this->alice);
        $this->alice->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());

        // When
        $changed = $before->changedIn($this->alice);

        // Then
        static::assertSame([], $changed);
    }
}
