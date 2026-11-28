<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use function base64_decode;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\A256Gcm;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\EcdhEsA256Kw;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodyOpener;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\JwtLibrary\SealedMessageBody;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJweException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function explode;
use function implode;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM as JoseA128Gcm;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use function json_decode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function strtr;

/**
 * Decision 0020
 */
final class MessageBodySealingTest extends TestCase
{
    /**
     * Decision 0011
     */
    private const string BODY = 'a:2:{s:9:"ipAddress";s:12:"203.0.113.42";s:5:"email";s:17:"alice@acme.example";}';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private SealedKeyProvider $provider;

    private JwtLibraryMessageBodySealer $sealer;

    private JwtLibraryMessageBodyOpener $opener;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->provider = new SealedKeyProvider($this->keys, Keys::opened());
        $this->sealer = new JwtLibraryMessageBodySealer($this->provider, Algorithms::messageSealing());
        $this->opener = new JwtLibraryMessageBodyOpener($this->provider, Algorithms::messageSealing());
        $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
    }

    #[Test]
    public function aSealedBodyOpensBackToWhatWasSealed(): void
    {
        // When
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // Then
        static::assertSame(self::BODY, $this->opener->open($this->tenant, $sealed));
    }

    #[Test]
    #[DataProvider('provideValuesOfTheBody')]
    public function aSealedBodyCarriesNoneOfTheValuesItHeld(string $value): void
    {
        // When
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // Then
        static::assertStringNotContainsString($value, $sealed);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesOfTheBody(): iterable
    {
        yield 'the address' => ['203.0.113.42'];
        yield 'the email' => ['alice@acme.example'];
        yield 'the shape of the payload' => ['ipAddress'];
    }

    /**
     * RFC 7516 §4.1.6
     */
    #[Test]
    public function theProtectedHeaderNamesTheKeyTheAlgorithmsAndTheScope(): void
    {
        // Given
        $key = $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());

        // When
        $header = self::protectedHeader($this->sealer->seal($this->tenant, self::BODY));

        // Then
        static::assertSame([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            'kid' => $key->kid,
            SealedMessageBody::TENANT_HEADER => 'acme',
        ], [
            'alg' => $header['alg'] ?? null,
            'enc' => $header['enc'] ?? null,
            'kid' => $header['kid'] ?? null,
            SealedMessageBody::TENANT_HEADER => $header[SealedMessageBody::TENANT_HEADER] ?? null,
        ]);
    }

    #[Test]
    public function aBodyIsNotOpenedUnderAnotherScope(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message was sealed for another scope than tenant "other"; it is not opened here.');

        // When
        $this->opener->open(Fixtures::tenant('other'), $sealed);
    }

    #[Test]
    public function aBodySealedToAKeyTheTenantNoLongerHoldsIsNotOpened(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);
        $key = $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIsOrContains('seals nothing to');

        // When
        $this->opener->open($this->tenant, $sealed);
    }

    /**
     * RFC 7516 §4.1.6
     *
     * @param array<string, string> $header
     */
    #[Test]
    #[DataProvider('provideHeadersThatNameNoKey')]
    public function aBodyThatNamesNoKeyIsNotOpened(array $header): void
    {
        // Given
        $sealed = $this->sealedWith([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            SealedMessageBody::TENANT_HEADER => $this->tenant->slug,
            ...$header,
        ]);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message does not name the key it was sealed to (RFC 7516 section 4.1.6).');

        // When
        $this->opener->open($this->tenant, $sealed);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideHeadersThatNameNoKey(): iterable
    {
        yield 'no "kid" at all' => [[]];
        yield 'an empty "kid"' => [['kid' => '']];
    }

    /**
     * RFC 7516 §4.1.6
     */
    #[Test]
    public function aSealedBodyNamesTheKeyItIsSealedToWithoutBeingOpened(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // When / Then
        static::assertSame(Keys::messagePair()->kid, SealedMessageBody::keyOf($this->tenant, $sealed));
    }

    #[Test]
    public function aBodySealedForAnotherTenantNamesNoKeyOfThisOne(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // When / Then
        static::assertNull(SealedMessageBody::keyOf(Fixtures::tenant('other', 'https://id.other.example'), $sealed));
    }

    /**
     * @param array<string, string> $header
     */
    #[Test]
    #[DataProvider('provideHeadersThatNameNoKey')]
    public function aBodyThatNamesNoKeyIsSealedToNone(array $header): void
    {
        // Given
        $sealed = $this->sealedWith([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            SealedMessageBody::TENANT_HEADER => $this->tenant->slug,
            ...$header,
        ]);

        // When / Then
        static::assertNull(SealedMessageBody::keyOf($this->tenant, $sealed));
    }

    #[Test]
    public function whatIsNoCompactJweIsSealedToNoKey(): void
    {
        // When / Then
        static::assertNull(SealedMessageBody::keyOf($this->tenant, 'not a JWE'));
    }

    /**
     * RFC 7516 §4.3
     */
    #[Test]
    public function aSealedBodyNamesTheTenantItIsSealedForWithoutBeingOpened(): void
    {
        // Given
        $sealed = $this->sealer->seal($this->tenant, self::BODY);

        // When / Then
        static::assertSame($this->tenant->slug, SealedMessageBody::tenantOf($sealed));
    }

    #[Test]
    public function aBodyWhoseProtectedHeaderNamesNoTenantIsSealedForNone(): void
    {
        // Given
        $sealed = $this->sealedWith([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            'kid' => Keys::messagePair()->kid,
        ]);

        // When / Then
        static::assertNull(SealedMessageBody::tenantOf($sealed));
    }

    #[Test]
    public function whatIsNoCompactJweIsSealedForNoTenant(): void
    {
        // When / Then
        static::assertNull(SealedMessageBody::tenantOf('not a JWE'));
    }

    #[Test]
    public function aBodySealedUnderAnotherAlgorithmThanTheKeyIsHeldForIsNotOpened(): void
    {
        // Given
        $key = $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());
        $sealed = $this->sealedWith([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A128GCM',
            'kid' => $key->kid,
            SealedMessageBody::TENANT_HEADER => $this->tenant->slug,
        ], new JoseA128Gcm());

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The body of the message was sealed under another algorithm than the key "%s" is held for.',
            $key->kid,
        ));

        // When
        $this->opener->open($this->tenant, $sealed);
    }

    /**
     * RFC 7516 §4.1.13
     */
    #[Test]
    public function aBodyThatMarksAParameterCriticalIsNotOpened(): void
    {
        // Given
        $sealed = $this->sealedWith([
            'alg' => 'ECDH-ES+A256KW',
            'enc' => 'A256GCM',
            'kid' => $this->provider->sealingKey($this->tenant, Algorithms::messageSeal())->kid,
            SealedMessageBody::TENANT_HEADER => $this->tenant->slug,
            'crit' => ['urn:example:must-understand'],
            'urn:example:must-understand' => true,
        ]);

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message uses an extension of JOSE this provider does not understand (RFC 7516 section 4.1.13).');

        // When
        $this->opener->open($this->tenant, $sealed);
    }

    /**
     * RFC 7518 §5.3
     */
    #[Test]
    public function aBodyWhoseInitializationVectorIsNotTheSizeOfItsContentEncryptionIsNotOpened(): void
    {
        // Given
        $parts = explode('.', $this->sealer->seal($this->tenant, self::BODY));
        $parts[2] = Base64Url::encode(random_bytes(16));

        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message cannot be opened as a JWE (RFC 7516 section 5.2).');

        // When
        $this->opener->open($this->tenant, implode('.', $parts));
    }

    #[Test]
    public function aBodyThatIsNotACompactJweIsNotOpened(): void
    {
        // Then
        $this->expectException(InvalidJweException::class);
        $this->expectExceptionMessageIs('The body of the message is not a compact JWE.');

        // When
        $this->opener->open($this->tenant, self::BODY);
    }

    #[Test]
    public function nothingIsSealedForATenantWithoutAKey(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('holds no MESSAGE-SEAL key');

        // When
        $this->sealer->seal(Fixtures::tenant('other'), self::BODY);
    }

    /**
     * @param array<string, mixed> $header
     */
    private function sealedWith(array $header, ?ContentEncryptionAlgorithm $contentEncryption = null): string
    {
        $key = $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());

        return new CompactSerializer()->serialize(
            new JWEBuilder(new AlgorithmManager([new EcdhEsA256Kw()->joseAlgorithm(), $contentEncryption ?? new A256Gcm()->joseAlgorithm()]))
                ->create()
                ->withPayload(self::BODY)
                ->withSharedProtectedHeader($header)
                ->addRecipient(new JWK([
                    ...$key->publicJwk,
                    'alg' => 'ECDH-ES+A256KW',
                ]))
                ->build(),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function protectedHeader(string $sealed): array
    {
        $decoded = base64_decode(strtr(explode('.', $sealed)[0], '-_', '+/'), true);
        static::assertIsString($decoded);
        $header = json_decode($decoded, true);
        static::assertIsArray($header);
        $members = [];
        foreach ($header as $member => $value) {
            static::assertIsString($member);
            $members[$member] = $value;
        }

        return $members;
    }

    private function activeKey(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
