<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\CredentialChangeChannelInterface;
use App\Credential\CredentialChangeChannels;
use App\Credential\ReplacedChannelInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Architecture §5.6
 */
final class CredentialChangeChannelsTest extends TestCase
{
    #[Test]
    public function theChannelsAreNamedInTheOrderTheyAreWired(): void
    {
        // Given
        $channels = new CredentialChangeChannels([self::channel('web_push'), self::channel('mail'), self::channel('sms')]);

        // When
        $names = $channels->names();

        // Then
        static::assertSame(['web_push', 'mail', 'sms'], $names);
    }

    #[Test]
    public function aChannelIsFoundByItsName(): void
    {
        // Given
        $mail = self::channel('mail');
        $channels = new CredentialChangeChannels([self::channel('web_push'), $mail]);

        // When
        $found = $channels->named('mail');

        // Then
        static::assertSame($mail, $found);
    }

    #[Test]
    public function aNameNoChannelGoesByFindsNone(): void
    {
        // Given
        $channels = new CredentialChangeChannels([self::channel('web_push')]);

        // When
        $found = $channels->named('mail');

        // Then
        static::assertNull($found);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aChannelThatReachesAReplacedChannelIsNoChannelOfEveryChange(): void
    {
        // Given
        $channels = new CredentialChangeChannels([self::channel('mail'), self::replacing('replaced_address', 'email')]);

        // When
        $names = $channels->names();

        // Then
        static::assertSame(['mail'], $names);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theChannelsThatReachAReplacedChannelAreFoundByItsClaim(): void
    {
        // Given
        $channels = new CredentialChangeChannels([
            self::replacing('replaced_address', 'email'),
            self::replacing('replaced_number', 'phone_number'),
        ]);

        // When
        $reaching = $channels->reaching('phone_number');

        // Then
        static::assertSame(['replaced_number'], $reaching);
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function aChannelThatReachesAReplacedChannelIsFoundByItsName(): void
    {
        // Given
        $replaced = self::replacing('replaced_address', 'email');
        $channels = new CredentialChangeChannels([self::channel('mail'), $replaced]);

        // When
        $found = $channels->named('replaced_address');

        // Then
        static::assertSame($replaced, $found);
    }

    #[Test]
    public function twoChannelsOfTheSameNameAreRefused(): void
    {
        // Given
        $channels = [self::channel('mail'), self::channel('mail')];

        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('Two channels that tell a person of a change to their credentials go by the name "mail": a notice for that name would reach the first one alone.');

        // When
        new CredentialChangeChannels($channels);
    }

    private static function replacing(string $name, string $claim): ReplacedChannelInterface
    {
        $channel = self::createStub(ReplacedChannelInterface::class);
        $channel->method('name')->willReturn($name);
        $channel->method('claim')->willReturn($claim);

        return $channel;
    }

    private static function channel(string $name): CredentialChangeChannelInterface
    {
        $channel = self::createStub(CredentialChangeChannelInterface::class);
        $channel->method('name')->willReturn($name);

        return $channel;
    }
}
