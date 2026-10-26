<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\JwtLibrary;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakeSignatureAlgorithm;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * One class per algorithm behind SignatureAlgorithmInterface, and the wired set over them. FAPI 2.0
 * §5.2.2 refuses RS256, so the provider signs with PS256 (RFC 7518 §3.5), ES256 (§3.4) and EdDSA over
 * Ed25519 (RFC 8037 §3.1) beside it; no HMAC (RFC 8725 §3.1), no "none".
 */
final class SignatureAlgorithmsTest extends TestCase
{
    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * RFC 7517 §4: a generated key names its algorithm, its kind and its use, and the public half of an
     * elliptic curve key names its curve (RFC 7518 §6.2.1.1, RFC 8037 §2).
     *
     * @param array<string, string> $expected the members the published JWK must carry
     */
    #[Test]
    #[DataProvider('provideWiredAlgorithms')]
    public function anAlgorithmGeneratesAKeyOfItsOwnKind(SignatureAlgorithmInterface $algorithm, array $expected): void
    {
        // Given
        $generator = new JwtLibraryKeyPairGenerator(Algorithms::everyUse());

        // When
        $pair = $generator->generate($algorithm);

        // Then
        static::assertSame($expected, self::members($pair->publicJwk, $expected));
        static::assertSame($algorithm, $pair->algorithm);
        static::assertArrayNotHasKey('d', $pair->publicJwk);
        static::assertArrayHasKey('d', $pair->privateJwk);
    }

    /**
     * RFC 7515 §5.2: what the provider signs with one of its algorithms, a relying party verifies against
     * the published JWK Set with that same algorithm.
     *
     * @param array<string, string> $ignoredMembers the members the generation test reads, unused here
     */
    #[Test]
    #[DataProvider('provideWiredAlgorithms')]
    public function anAlgorithmSignsAJwsTheLibraryVerifiesAgainstThePublishedSet(SignatureAlgorithmInterface $algorithm, array $ignoredMembers): void
    {
        // Given
        $keys = $this->provider($algorithm);

        // When
        $jws = new JwtLibraryJwsSigner($keys, Algorithms::all())->sign($this->tenant, $algorithm, '{"sub":"alice"}');

        // Then
        $unserialized = new CompactSerializer()->unserialize($jws);
        static::assertSame($algorithm->name(), $unserialized->getSignature(0)->getProtectedHeader()['alg']);
        static::assertTrue(new JWSVerifier(Algorithms::all()->manager())->verifyWithKeySet(
            $unserialized,
            JWKSet::createFromKeyData($keys->publicKeys($this->tenant)->toJwks()),
            0,
        ));
    }

    /**
     * OIDC Core §3.1.3.6 reads the hash of "at_hash" and "c_hash" from the "alg"; Ed25519 signs over
     * SHA-512 (RFC 8032 §5.1).
     */
    #[Test]
    #[DataProvider('provideDigests')]
    public function anAlgorithmNamesTheDigestItsHashClaimsHalve(SignatureAlgorithmInterface $algorithm, string $digest): void
    {
        // When / Then
        static::assertSame($digest, $algorithm->digestAlgorithm());
    }

    /**
     * @return iterable<string, array{SignatureAlgorithmInterface, array<string, string>}>
     */
    public static function provideWiredAlgorithms(): iterable
    {
        yield 'RS256' => [
            Algorithms::rs256(),
            [
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
            ],
        ];
        yield 'PS256' => [
            Algorithms::ps256(),
            [
                'kty' => 'RSA',
                'alg' => 'PS256',
                'use' => 'sig',
            ],
        ];
        yield 'ES256' => [
            Algorithms::es256(),
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'alg' => 'ES256',
                'use' => 'sig',
            ],
        ];
        yield 'EdDSA' => [
            Algorithms::edDsa(),
            [
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'alg' => 'EdDSA',
                'use' => 'sig',
            ],
        ];
    }

    /**
     * @return iterable<string, array{SignatureAlgorithmInterface, string}>
     */
    public static function provideDigests(): iterable
    {
        yield 'RS256' => [Algorithms::rs256(), 'sha256'];
        yield 'PS256' => [Algorithms::ps256(), 'sha256'];
        yield 'ES256' => [Algorithms::es256(), 'sha256'];
        yield 'EdDSA' => [Algorithms::edDsa(), 'sha512'];
    }

    /**
     * OIDC Registration §2: what signs when nobody named an algorithm is the first wired one.
     */
    #[Test]
    public function theDefaultIsTheFirstWiredAlgorithm(): void
    {
        // Given
        $algorithms = new JoseSignatureAlgorithms([Algorithms::es256(), Algorithms::rs256()]);

        // When / Then
        static::assertSame(Algorithms::es256(), $algorithms->defaultAlgorithm());
    }

    #[Test]
    public function theWiredAlgorithmsAreThoseGivenInOrder(): void
    {
        // When
        $names = array_map(static fn (SignatureAlgorithmInterface $algorithm): string => $algorithm->name(), Algorithms::all()->all());

        // Then
        static::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA'], $names);
    }

    #[Test]
    public function anAlgorithmNothingWiredSignsWithIsRefused(): void
    {
        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider does not sign with "HS256"; it signs with RS256, PS256, ES256, EdDSA.');

        // When
        Algorithms::all()->named('HS256');
    }

    #[Test]
    public function theSameAlgorithmWiredTwiceIsAFault(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The algorithm "RS256" is wired twice.');

        // When
        new JoseSignatureAlgorithms([Algorithms::rs256(), Algorithms::rs256()]);
    }

    #[Test]
    public function aProviderWiredWithNoAlgorithmIsAFault(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider signs with at least one algorithm.');

        // When
        new JoseSignatureAlgorithms([]);
    }

    /**
     * Issue #98: a name no registry carries is refused with what each of them had to say about it, so
     * that an operator who typed one reads what this provider does sign with, is encrypted to with, hands
     * out and seals its own messages to.
     */
    #[Test]
    public function aNameNoRegistryCarriesIsRefusedWithWhatEachOfThemServes(): void
    {
        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider does not sign with "HS256"; it signs with RS256, PS256, ES256, EdDSA. '
        . 'This provider is not encrypted to with "HS256"; it is encrypted to with ECDH-ES+A256KW, RSA-OAEP-256. '
        . 'This provider hands out no key named "HS256"; it hands out VAPID. '
        . 'This provider seals no message body to a key named "HS256"; it seals to MESSAGE-SEAL.');

        // When
        Algorithms::everyUse()->named('HS256');
    }

    /**
     * The same reading of a deployment nobody encrypts to, that reaches nobody by push and that seals
     * nothing: a registry wired with nothing says so rather than listing nothing.
     */
    #[Test]
    public function aNameNoRegistryCarriesIsRefusedWithWhatEachOfThemHoldsNothingOf(): void
    {
        // Given
        $algorithms = Algorithms::readAsOne([
            Algorithms::all(),
            Algorithms::noKeyEncryption(),
            Algorithms::noApplicationServer(),
            Algorithms::noMessageSealing(),
        ]);

        // Then
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessageIs('This provider does not sign with "HS256"; it signs with RS256, PS256, ES256, EdDSA. '
        . 'This provider is encrypted to with nothing; "HS256" is not read. '
        . 'This provider hands out no key named "HS256"; it hands out none. '
        . 'This provider seals no message body to a key named "HS256"; it seals to none.');

        // When
        $algorithms->named('HS256');
    }

    /**
     * The first refusal is the trail: what the registry a name would most likely have belonged to said
     * about it is what a reader of the exception follows.
     */
    #[Test]
    public function theRefusalOfTheFirstRegistryIsTheTrail(): void
    {
        // When
        try {
            Algorithms::everyUse()->named('HS256');
            static::fail('A name no registry carries is refused.');
        } catch (UnsupportedAlgorithmException $refusal) {
            // Then
            static::assertSame(
                'This provider does not sign with "HS256"; it signs with RS256, PS256, ES256, EdDSA.',
                $refusal->getPrevious()?->getMessage(),
            );
        }
    }

    /**
     * Open by addition: an algorithm the core, the module and the bundle have never heard of is generated,
     * signed with and published because it was wired, and for no other reason.
     */
    #[Test]
    public function anAlgorithmNoLineOfTheProviderKnowsAboutSignsAndIsPublished(): void
    {
        // Given
        $unwired = new FakeSignatureAlgorithm();
        $algorithms = new JoseSignatureAlgorithms([$unwired]);
        $repository = new InMemoryTenantKeyRepository();
        $pair = new JwtLibraryKeyPairGenerator(
            Algorithms::readAsOne([
                $algorithms,
                Algorithms::noKeyEncryption(),
                Algorithms::noApplicationServer(),
                Algorithms::noMessageSealing(),
            ]),
        )->generate($unwired);
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $unwired,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $repository->save($key);
        $keys = new SealedKeyProvider($repository, Keys::opened());

        // When
        $jws = new JwtLibraryJwsSigner($keys, $algorithms)->sign($this->tenant, $unwired, '{"sub":"alice"}');

        // Then
        static::assertSame($key, new JwtLibraryJwsVerifier($keys, $algorithms)->verify($this->tenant, $jws)->key);
        static::assertSame(
            [[
                'kid' => $pair->kid,
                'alg' => 'ES256UNWIRED',
                'use' => 'sig',
            ]],
            array_map(static fn (array $jwk): array => self::members($jwk, [
                'kid' => '',
                'alg' => '',
                'use' => '',
            ]), $keys->publicKeys($this->tenant)->toJwks()['keys']),
        );
    }

    #[Test]
    public function anRsaKeyUnderTheMinimumIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('RSA keys are at least 2048 bits, in whole bytes.');

        // When
        new RsaKeyBits(1024);
    }

    #[Test]
    public function anRsaKeyThatIsNotAWholeNumberOfBytesIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('RSA keys are at least 2048 bits, in whole bytes.');

        // When
        new RsaKeyBits(2049);
    }

    private function provider(SignatureAlgorithmInterface $algorithm): SealedKeyProvider
    {
        $repository = new InMemoryTenantKeyRepository();
        $pair = $algorithm === Algorithms::rs256() ? Keys::pair() : new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate($algorithm);
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
        $repository->save($key);

        return new SealedKeyProvider($repository, Keys::opened());
    }

    /**
     * @param array<string, string> $jwk
     * @param array<string, string> $expected
     *
     * @return array<string, string>
     */
    private static function members(array $jwk, array $expected): array
    {
        $members = [];
        foreach ($expected as $member => $ignored) {
            $members[$member] = $jwk[$member] ?? '';
        }

        return $members;
    }
}
