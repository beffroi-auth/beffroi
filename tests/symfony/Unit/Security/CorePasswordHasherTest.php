<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Security;

use Beffroi\Core\Bridge\Password\Algorithm\Argon2i;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use App\Security\CorePasswordHasher;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\PasswordHasherRegistry;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Beffroi\Core\Domain\Credential\PasswordHash;
use const PASSWORD_BCRYPT;
use function password_hash;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PasswordHasher\Exception\InvalidPasswordException;

/**
 * Architecture §5.4
 */
final class CorePasswordHasherTest extends TestCase
{
    private CorePasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = self::hasher();
    }

    #[Test]
    public function aHashOfTheCoreGoesThroughTheStringOfTheComponentWithoutLoss(): void
    {
        // Given
        $hash = new PasswordHash(new Pbkdf2Sha256(), 'ZGlnZXN0', [
            'salt' => 'c2FsdA',
            'iterations' => 27500,
        ]);

        // When
        $decoded = self::hasher()->decode(CorePasswordHasher::encode($hash));

        // Then
        static::assertNotNull($decoded);
        static::assertSame(Pbkdf2Sha256::NAME, $decoded->algorithm->name());
        static::assertSame('ZGlnZXN0', $decoded->encoded);
        static::assertSame(
            [
                'salt' => 'c2FsdA',
                'iterations' => 27500,
            ],
            $decoded->parameters,
        );
    }

    #[Test]
    public function hashingProducesWhatTheCoreProduces(): void
    {
        // When
        $encoded = $this->hasher->hash('correct horse battery staple');

        // Then
        $hash = self::hasher()->decode($encoded);
        static::assertNotNull($hash);
        static::assertSame(Argon2id::NAME, $hash->algorithm->name());
        static::assertFalse($this->hasher->needsRehash($encoded));
    }

    #[Test]
    public function aHashOfTheCoreVerifiesTheRightPasswordOnly(): void
    {
        // Given
        $encoded = $this->hasher->hash('correct horse battery staple');

        // When / Then
        static::assertTrue($this->hasher->verify($encoded, 'correct horse battery staple'));
        static::assertFalse($this->hasher->verify($encoded, 'incorrect horse'));
    }

    #[Test]
    public function aHashOfAnotherAlgorithmIsVerifiedAndNeedsARehash(): void
    {
        // Given
        $encoded = CorePasswordHasher::encode(new PasswordHash(new Bcrypt(), password_hash('correct horse battery staple', PASSWORD_BCRYPT, [
            'cost' => 4,
        ])));

        // When / Then
        static::assertTrue($this->hasher->verify($encoded, 'correct horse battery staple'));
        static::assertFalse($this->hasher->verify($encoded, 'incorrect horse'));
        static::assertTrue($this->hasher->needsRehash($encoded));
    }

    #[Test]
    #[DataProvider('provideNotAHash')]
    public function aStringThatIsNotAHashOfTheCoreVerifiesNothing(string $encoded): void
    {
        // When / Then
        static::assertNull(self::hasher()->decode($encoded));
        static::assertFalse($this->hasher->verify($encoded, 'correct horse battery staple'));
        static::assertFalse($this->hasher->needsRehash($encoded));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotAHash(): iterable
    {
        yield 'a PHC string' => ['$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA'];
        yield 'empty' => [''];
        yield 'not JSON' => ['{'];
        yield 'not an object' => ['"hash"'];
        yield 'unknown algorithm' => ['{"algorithm":"md5","encoded":"x","parameters":[]}'];
        yield 'no encoded form' => ['{"algorithm":"argon2id","parameters":[]}'];
        yield 'empty encoded form' => ['{"algorithm":"argon2id","encoded":"","parameters":[]}'];
        yield 'parameters not a map' => ['{"algorithm":"argon2id","encoded":"x","parameters":"salt"}'];
        yield 'parameter not a string or an int' => ['{"algorithm":"argon2id","encoded":"x","parameters":{"salt":null}}'];
        yield 'parameter without a name' => ['{"algorithm":"argon2id","encoded":"x","parameters":["salt"]}'];
    }

    #[Test]
    public function aHashNoHasherHandlesIsAWrongPassword(): void
    {
        // Given
        $encoded = CorePasswordHasher::encode(new PasswordHash(new Pbkdf2Sha512(), 'ZGlnZXN0', [
            'salt' => 'c2FsdA',
        ]));

        // When / Then
        static::assertFalse($this->hasher->verify($encoded, 'correct horse battery staple'));
        static::assertFalse($this->hasher->needsRehash($encoded));
    }

    /**
     * RFC 8265 §8.2, decision 0065
     */
    #[Test]
    public function aPasswordIsHashedInTheFormTheProfileEnforces(): void
    {
        // Given
        $encoded = $this->hasher->hash("correct\u{00A0}horse battery staple");

        // When
        $hash = self::hasher()->decode($encoded) ?? static::fail('The hash is no hash of the core.');

        // Then
        static::assertTrue(new NativePasswordHasher()->verify($hash, 'correct horse battery staple'));
    }

    /**
     * RFC 8265 §4.1, §4.3
     */
    #[Test]
    public function aPasswordTheProfileRefusesIsNotHashed(): void
    {
        // Then
        $this->expectException(InvalidPasswordException::class);

        // When
        $this->hasher->hash("my cat is a \u{0009}by");
    }

    /**
     * RFC 8265 §4.2.3
     */
    #[Test]
    public function aPasswordTypedInAnotherFormVerifiesTheHashOfItsEnforcedForm(): void
    {
        // Given
        $encoded = $this->hasher->hash('correct horse battery staple');

        // When / Then
        static::assertTrue($this->hasher->verify($encoded, "correct horse battery\u{3000}staple"));
    }

    /**
     * RFC 8265 §6.2
     */
    #[Test]
    public function aHashOfTheBytesAsTypedBeforeTheProfileVerifiesThoseBytes(): void
    {
        // Given
        $encoded = CorePasswordHasher::encode(new NativePasswordHasher()->hash("correct\u{00A0}horse"));

        // When / Then
        static::assertTrue($this->hasher->verify($encoded, "correct\u{00A0}horse"));
    }

    private static function hasher(): CorePasswordHasher
    {
        return new CorePasswordHasher(
            new PasswordHasherRegistry([new NativePasswordHasher()], self::algorithms()),
            self::algorithms(),
        );
    }

    private static function algorithms(): WiredPasswordAlgorithms
    {
        return new WiredPasswordAlgorithms([new Argon2id(), new Argon2i(), new Bcrypt(), new Pbkdf2Sha256(), new Pbkdf2Sha512()]);
    }
}
