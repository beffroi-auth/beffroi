<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Key;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Domain\Key\UpstreamEncryptionKeys;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strpos;
use function substr;

/**
 * spec/saml.md S-64, S-65, section 6.12 step 1: the keys one upstream identity provider encrypts for, among the keys of
 * the tenant in service, the newest first, and one material the key of one provider only.
 */
final class UpstreamEncryptionKeysTest extends TestCase
{
    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * S-65: the keys of the provider, the newest first, which is the order its metadata list their certificates in
     * and the order they are tried in.
     */
    #[Test]
    public function theKeysOfTheProviderComeNewestFirst(): void
    {
        // Given
        $current = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $current->activate(Fixtures::now());
        $next = SamlKeys::encryptionKey($this->tenant, self::PROVIDER, 1, Fixtures::now()->modify('+1 day'));

        // When
        $keys = UpstreamEncryptionKeys::of([$current, $next], self::PROVIDER);

        // Then
        static::assertSame([$next, $current], $keys->keys);
    }

    /**
     * S-64: the keys of another provider, the SAML signing key and the keys of any other algorithm, a key of another
     * type among them, are not the provider's.
     */
    #[Test]
    public function onlyTheKeysOfTheProviderAreItsOwn(): void
    {
        // Given
        $own = SamlKeys::encryptionKey($this->tenant, self::PROVIDER);
        $inService = [
            SamlKeys::activeKey($this->tenant),
            SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1),
            $own,
            SamlKeys::key($this->tenant, Keys::encryptionPair()),
        ];

        // When
        $keys = UpstreamEncryptionKeys::of($inService, self::PROVIDER);

        // Then
        static::assertSame([$own], $keys->keys);
    }

    /**
     * Section 6.13 step 1: a provider for which the tenant holds no key in service has none.
     */
    #[Test]
    public function aProviderWithoutAKeyHasNone(): void
    {
        // Given
        $inService = [SamlKeys::activeKey($this->tenant), SamlKeys::encryptionKey($this->tenant, self::OTHER_PROVIDER, 1)];

        // When
        $keys = UpstreamEncryptionKeys::of($inService, self::PROVIDER);

        // Then
        static::assertSame([], $keys->keys);
    }

    /**
     * S-64: a key of the provider whose modulus another key of the tenant in service holds, the key of another provider
     * or the SAML signing key, is refused, whichever of the two is asked for, naming the two algorithms and not the
     * material; one integer spelt otherwise, a leading zero octet or other trailing bits, is the same modulus, and a
     * modulus that is not base64url, a line feed in it, is refused rather than compared as text.
     *
     * @param list<TenantKey> $inService
     */
    #[Test]
    #[DataProvider('provideSharedMaterials')]
    public function aKeyHoldingTheModulusOfAnotherKeyIsRefused(array $inService, string $provider, string $message): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs($message);

        // When
        UpstreamEncryptionKeys::of($inService, $provider);
    }

    /**
     * @return iterable<string, array{list<TenantKey>, string, string}>
     */
    public static function provideSharedMaterials(): iterable
    {
        $tenant = Fixtures::tenant();
        $first = SamlKeys::encryptionKey($tenant, self::PROVIDER);
        $second = self::sameMaterial(SamlKeys::encryptionKey($tenant, self::OTHER_PROVIDER), 'second');

        yield 'the key of another provider, asked for the first' => [
            [$first, $second],
            self::PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-a.example/metadata holds the modulus of a key of SAML-ENCRYPTION:https://idp-b.example/metadata: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        yield 'the key of another provider, asked for the second' => [
            [$first, $second],
            self::OTHER_PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-b.example/metadata holds the modulus of a key of SAML-ENCRYPTION:https://idp-a.example/metadata: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        yield 'the SAML signing key' => [
            [SamlKeys::activeKey($tenant), self::sameMaterial(SamlKeys::encryptionKey($tenant, self::PROVIDER), 'signing', SamlKeys::pair()->publicJwk['n'])],
            self::PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-a.example/metadata holds the modulus of a key of SAML-SIGNING: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        $modulus = SamlKeys::encryptionPair()->publicJwk['n'];
        yield 'the same integer with a leading zero octet' => [
            [
                $first,
                self::sameMaterial(
                    SamlKeys::encryptionKey($tenant, self::OTHER_PROVIDER),
                    'second',
                    Base64Url::encode("\0" . (Base64Url::decode($modulus) ?? '')),
                ),
            ],
            self::OTHER_PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-b.example/metadata holds the modulus of a key of SAML-ENCRYPTION:https://idp-a.example/metadata: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        yield 'the same integer with other trailing bits' => [
            [$first, self::sameMaterial(SamlKeys::encryptionKey($tenant, self::OTHER_PROVIDER), 'second', self::withOtherTrailingBits($modulus))],
            self::OTHER_PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-b.example/metadata holds the modulus of a key of SAML-ENCRYPTION:https://idp-a.example/metadata: one key belongs to one identity provider (spec/saml.md S-64).',
        ];
        yield 'a line feed in the modulus of the copy, asked for the first' => [
            [
                $first,
                self::sameMaterial(SamlKeys::encryptionKey($tenant, self::OTHER_PROVIDER), 'second', substr($modulus, 0, 64) . "\n" . substr($modulus, 64)),
            ],
            self::PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-b.example/metadata carries a modulus that is not base64url (RFC 7518 §6.3.1.1, spec/saml.md S-64).',
        ];
        yield 'a line feed in the modulus of the copy, asked for the copy' => [
            [
                $first,
                self::sameMaterial(SamlKeys::encryptionKey($tenant, self::OTHER_PROVIDER), 'second', substr($modulus, 0, 64) . "\n" . substr($modulus, 64)),
            ],
            self::OTHER_PROVIDER,
            'A key of SAML-ENCRYPTION:https://idp-b.example/metadata carries a modulus that is not base64url (RFC 7518 §6.3.1.1, spec/saml.md S-64).',
        ];
    }

    /**
     * The same base64url text but for the bits of its last character that encode no octet, which a decoder reads past:
     * a modulus of 2 048 bits, 256 octets, ends on one octet in two characters, four of whose bits are such.
     */
    private static function withOtherTrailingBits(string $modulus): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $last = strpos($alphabet, $modulus[-1]);
        static::assertIsInt($last);

        return substr($modulus, 0, -1) . $alphabet[$last | 0b0001];
    }

    /**
     * The same key under another "kid", its modulus the one given or the one of the first pair of the providers: what a
     * store that kept the material twice would hold.
     */
    private static function sameMaterial(TenantKey $key, string $kid, ?string $modulus = null): TenantKey
    {
        return new TenantKey(
            $kid,
            $key->tenant,
            $key->algorithm,
            [
                ...$key->publicJwk,
                'kid' => $kid,
                'n' => $modulus ?? SamlKeys::encryptionPair()->publicJwk['n'],
            ],
            $key->sealedPrivateJwk,
            $key->createdAt,
            $key->activationDueAt,
        );
    }
}
