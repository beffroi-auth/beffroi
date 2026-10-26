<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Saml\Bridge\Model\ProviderDecryptionKey;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\OaepHash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-66, section 6.13 step 4: the keys of one provider tried in turn, in their order, the first session
 * key that unwraps answered, nothing when none does.
 */
final class ProviderDecryptionKeyTest extends TestCase
{
    /**
     * S-66: the first key that unwraps answers, and the keys after it are not asked.
     */
    #[Test]
    public function theFirstKeyThatUnwrapsAnswers(): void
    {
        // Given
        $last = self::createMock(DecryptionKeyInterface::class);
        $last->expects(static::never())->method('unwrap');
        $key = new ProviderDecryptionKey([self::unwrapping(null), self::unwrapping('session key'), $last]);

        // When
        $sessionKey = $key->unwrap('wrapped', OaepHash::Sha1);

        // Then
        static::assertSame('session key', $sessionKey);
    }

    /**
     * S-66, enc.md E-6: when no key of the provider unwraps, nothing is answered, never why.
     */
    #[Test]
    public function noKeyThatUnwrapsAnswersNothing(): void
    {
        // Given
        $key = new ProviderDecryptionKey([self::unwrapping(null), self::unwrapping(null)]);

        // When / Then
        static::assertNull($key->unwrap('wrapped', OaepHash::Sha1));
    }

    /**
     * S-66: each key is handed the wrapped session key and the hash it was wrapped under, as Enc's Decryptor hands them.
     */
    #[Test]
    public function eachKeyIsHandedTheWrappedKeyAndItsHash(): void
    {
        // Given
        $first = self::createMock(DecryptionKeyInterface::class);
        $first->expects(static::once())->method('unwrap')->with('wrapped', OaepHash::Sha256)->willReturn(null);
        $key = new ProviderDecryptionKey([$first, self::unwrapping('session key')]);

        // When
        $sessionKey = $key->unwrap('wrapped', OaepHash::Sha256);

        // Then
        static::assertSame('session key', $sessionKey);
    }

    private static function unwrapping(?string $sessionKey): DecryptionKeyInterface
    {
        $key = self::createStub(DecryptionKeyInterface::class);
        $key->method('unwrap')->willReturn($sessionKey);

        return $key;
    }
}
