<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctrine\PersonalData;

use function array_unique;
use function array_values;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\BlindIndexInterface;
use Symfony\Component\KeyManagement\Test\InMemoryDataKeyStore;

/**
 * Decision 0011
 */
final class BlindIndexedColumnsTest extends TestCase
{
    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    #[DataProvider('provideUsernamesThatCompareEqual')]
    public function twoUsernamesThatCompareEqualAreTheSameTag(string $one, string $other): void
    {
        // Given
        $index = self::index('username');

        // When / Then
        static::assertSame($index->of($one), $index->of($other));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUsernamesThatCompareEqual(): iterable
    {
        yield 'by case' => ['Alice', 'alice'];
        yield 'by width' => ["\u{FF41}\u{FF4C}\u{FF49}\u{FF43}\u{FF45}", 'alice'];
        yield 'by composition' => ["jose\u{0301}", "jos\u{00E9}"];
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function twoUsernamesThatDoNotCompareEqualAreTwoTags(): void
    {
        // Given
        $index = self::index('username');

        // When / Then
        static::assertNotSame($index->of('fussball'), $index->of('fußball'));
    }

    /**
     * A username written before RFC 8265 §3.3 applied, which it refuses, keeps the tag 0.1 derived for it.
     */
    #[Test]
    public function aUsernameTheProfileRefusesIsTheTagItHadAsWritten(): void
    {
        // Given
        [$index, $asWritten] = self::usernameIndexes();

        // When / Then
        static::assertSame($asWritten->of('Jean Dupont'), $index->of('Jean Dupont'));
    }

    /**
     * RFC 8265 §3.3.4: so that a lookup that tries the name as written first finds nobody else.
     */
    #[Test]
    public function theTagOfAUsernameAsWrittenIsTheTagOfItsEnforcedFormWhenItIsThatForm(): void
    {
        // Given
        [$index, $asWritten] = self::usernameIndexes();

        // When / Then
        static::assertSame($index->of('alice'), $asWritten->of('alice'));
    }

    /**
     * RFC 8265 §3.3.4
     */
    #[Test]
    public function theTagOfAUsernameAsWrittenIsNotTheTagOfItsEnforcedFormWhenItIsAnother(): void
    {
        // Given
        [$index, $asWritten] = self::usernameIndexes();

        // When / Then
        static::assertNotSame($index->of('Alice'), $asWritten->of('Alice'));
    }

    /**
     * RFC 5321 §2.4
     */
    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsDomainIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@Example.org'), $index->of('Ada@EXAMPLE.ORG'));
    }

    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsLocalPartIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@example.org'), $index->of('ada@example.org'));
    }

    /**
     * RFC 6532 §3.1
     */
    #[Test]
    public function anAddressDifferingOnlyByTheCompositionOfItsLocalPartIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of("jose\u{0301}@example.org"), $index->of("jos\u{00E9}@example.org"));
    }

    #[Test]
    public function anAddressDifferingByItsLocalPartIsADifferentTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertNotSame($index->of('ada@example.org'), $index->of('grace@example.org'));
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function theTwoColumnsOfOneTenantDoNotShareTheirTagForOneValue(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $reference = $store->current('acme.blind_index')->reference;

        // When
        $username = BlindIndexedColumns::of(User::class, 'username')->index($store, $reference);
        $email = BlindIndexedColumns::of(User::class, 'email')->index($store, $reference);

        // Then
        static::assertNotSame($username->of('ada@example.org'), $email->of('ada@example.org'));
    }

    #[Test]
    public function noTwoColumnsNameTheirIndexAlike(): void
    {
        // When
        $tags = BlindIndexedColumns::tags();

        // Then
        static::assertSame($tags, array_values(array_unique($tags)));
    }

    #[Test]
    public function aColumnNoIndexIsDeclaredOnIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No blind index is declared on "Beffroi\Core\Domain\Identity\User::$phoneNumber", so nothing can be searched by it.');

        // When
        BlindIndexedColumns::of(User::class, 'phoneNumber');
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function theScopeOfTheIndexKeyIsNoFamilyOfColumns(): void
    {
        // When / Then
        static::assertArrayNotHasKey(BlindIndexedColumns::SCOPE, EncryptedColumnTypes::FAMILIES);
    }

    /**
     * @return array{BlindIndexInterface, BlindIndexInterface} the index of the username, and the one 0.1 derived
     */
    private static function usernameIndexes(): array
    {
        $store = new InMemoryDataKeyStore();
        $reference = $store->current('acme.blind_index')->reference;

        return [
            BlindIndexedColumns::of(User::class, 'username')->index($store, $reference),
            BlindIndexedColumns::usernameAsWritten()->index($store, $reference),
        ];
    }

    private static function index(string $property): BlindIndexInterface
    {
        $store = new InMemoryDataKeyStore();

        return BlindIndexedColumns::of(User::class, $property)->index($store, $store->current('acme.blind_index')->reference);
    }
}
