<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\PersonalData;

use function array_unique;
use function array_values;
use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\BlindIndexInterface;
use Symfony\Component\KeyManagement\Test\InMemoryDataKeyStore;

/**
 * Decision 0011: what of a value is actually indexed is a rule of the column and not of the call sites,
 * because an index derived on one projection and searched on another silently matches nothing.
 */
final class BlindIndexedColumnsTest extends TestCase
{
    /**
     * A username is indexed byte for byte: folding its case would be a rule of the identity model, which
     * trims a username and nothing more, and not a rule of an index.
     */
    #[Test]
    public function aUsernameDifferingOnlyByItsCaseIsADifferentTag(): void
    {
        // Given
        $index = self::index('username');

        // When / Then
        static::assertNotSame($index->of('alice'), $index->of('Alice'));
    }

    /**
     * RFC 5321 §2.4: the domain of an address is case-insensitive, so two addresses that differ only by the
     * case of their domain share a tag.
     */
    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsDomainIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@Example.org'), $index->of('Ada@EXAMPLE.ORG'));
    }

    /**
     * Issue #781: the address is folded whole, its local part as well, every server a person reads their
     * mail on ignoring its case: two persons never hold one mailbox under two spellings of it.
     */
    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsLocalPartIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@example.org'), $index->of('ada@example.org'));
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
     * One index key per tenant, and each column names its index after itself, so the two columns of one
     * tenant derive their tags under subkeys that differ: a username that happens to be an address does
     * not share the tag of that address, and whoever reads the two columns learns nothing of which rows of
     * one hold a value of the other (decision 0011).
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

    /**
     * An index is named after the column its tags are written to, and that name is what separates its
     * subkey from that of every other index over the key of the tenant: two columns named alike would be
     * two columns sharing their tags, which naming them exists to prevent.
     */
    #[Test]
    public function noTwoColumnsNameTheirIndexAlike(): void
    {
        // When
        $tags = BlindIndexedColumns::tags();

        // Then
        static::assertSame($tags, array_values(array_unique($tags)));
    }

    /**
     * A query that asks for a column no index is declared on is a query that would match nothing, so it is
     * refused where it is written rather than answered with an empty result.
     */
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
     * The scope the index key is minted under is no family of columns, so the two cannot share a store and
     * the index key cannot retire with them (decision 0018).
     */
    #[Test]
    public function theScopeOfTheIndexKeyIsNoFamilyOfColumns(): void
    {
        // When / Then
        static::assertArrayNotHasKey(BlindIndexedColumns::SCOPE, EncryptedColumnTypes::FAMILIES);
    }

    private static function index(string $property): BlindIndexInterface
    {
        $store = new InMemoryDataKeyStore();

        return BlindIndexedColumns::of(User::class, $property)->index($store, $store->current('acme.blind_index')->reference);
    }
}
