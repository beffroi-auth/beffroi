<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Key;

use DateTimeImmutable;
use function decoct;
use function file_get_contents;
use function file_put_contents;
use function fileperms;
use function glob;
use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Saml\JoseSamlEncryptionAlgorithms;
use Beffroi\Bundle\Saml\SamlEncryption;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyFamily;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use DateInterval;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Domain\Key\KeyStatus;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Filesystem\Filesystem;
use function sys_get_temp_dir;
use function uniqid;

/**
 * Architecture §3.3: the sealed keys as files, one per key, under the tenant's slug.
 */
final class FileTenantKeyRepositoryTest extends TestCase
{
    private string $directory;

    private FileTenantKeyRepository $repository;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-keys-' . uniqid('', true);
        $this->repository = new FileTenantKeyRepository($this->directory, Algorithms::all());
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    #[Test]
    public function aKeyIsSavedAsAFileUnderTheSlugOfItsTenant(): void
    {
        // Given
        $key = self::key(Fixtures::tenant(), Keys::pair()->kid);

        // When
        $this->repository->save($key);

        // Then
        static::assertFileExists($this->directory . '/acme/' . $key->kid . '.json');
    }

    #[Test]
    public function aSavedKeyIsReadBackWithEverythingItCarries(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = new TenantKey(
            Keys::pair()->kid,
            $tenant,
            Algorithms::rs256(),
            Keys::pair()->publicJwk,
            Keys::sealer()->seal($tenant, Keys::pair()->privateJwk),
            Fixtures::now(),
            Fixtures::now()->modify('+6 minutes'),
        );
        $this->repository->save($key);

        // When
        $found = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');

        // Then
        static::assertNotSame($key, $found);
        static::assertSame($key->kid, $found->kid);
        static::assertSame($tenant, $found->tenant);
        static::assertSame('RS256', $found->algorithm->name());
        static::assertSame($key->publicJwk, $found->publicJwk);
        static::assertSame($key->sealedPrivateJwk, $found->sealedPrivateJwk);
        static::assertSame(Keys::pair()->privateJwk, Keys::sealer()->unseal($tenant, $found->sealedPrivateJwk));
        static::assertEquals(Fixtures::now(), $found->createdAt);
        static::assertEquals(Fixtures::now()->modify('+6 minutes'), $found->activationDueAt);
        static::assertSame(KeyStatus::Staged, $found->status);
        static::assertNull($found->activatedAt);
        static::assertNull($found->retiringAt);
        static::assertNull($found->retirementDueAt);
        static::assertNull($found->retiredAt);
    }

    #[Test]
    public function anActiveStatusAndItsDateSurviveTheRoundTrip(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = self::key($tenant, Keys::pair()->kid);
        $key->activate(Fixtures::now()->modify('+6 minutes'));
        $this->repository->save($key);

        // When
        $active = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');

        // Then
        static::assertSame(KeyStatus::Active, $active->status);
        static::assertEquals(Fixtures::now()->modify('+6 minutes'), $active->activatedAt);
        static::assertNull($active->retiringAt);
    }

    #[Test]
    public function aRetiringStatusAndItsDatesSurviveTheRoundTrip(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = self::activeKey($tenant, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now()->modify('+1 day'), Fixtures::now()->modify('+1 day +10 minutes'));
        $this->repository->save($key);

        // When
        $retiring = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');

        // Then
        static::assertSame(KeyStatus::Retiring, $retiring->status);
        static::assertEquals(Fixtures::now(), $retiring->activatedAt);
        static::assertEquals(Fixtures::now()->modify('+1 day'), $retiring->retiringAt);
        static::assertEquals(Fixtures::now()->modify('+1 day +10 minutes'), $retiring->retirementDueAt);
        static::assertNull($retiring->retiredAt);
    }

    #[Test]
    public function aRetiredStatusAndItsDatesSurviveTheRoundTrip(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = self::activeKey($tenant, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now()->modify('+1 day'), Fixtures::now()->modify('+2 days'));
        $key->retire(Fixtures::now()->modify('+2 days'));
        $this->repository->save($key);

        // When
        $retired = $this->repository->find($tenant, $key->kid) ?? static::fail('The key is found.');

        // Then
        static::assertSame(KeyStatus::Retired, $retired->status);
        static::assertEquals(Fixtures::now()->modify('+1 day'), $retired->retiringAt);
        static::assertEquals(Fixtures::now()->modify('+2 days'), $retired->retirementDueAt);
        static::assertEquals(Fixtures::now()->modify('+2 days'), $retired->retiredAt);
    }

    /**
     * TenantKeyRepositoryInterface::findInService(): staged, active and retiring keys, in creation order;
     * findActive(): never a staged key.
     */
    #[Test]
    public function theActiveKeyIsFoundAmongTheOthers(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->saveThreeKeys($tenant);

        // When
        $active = $this->repository->findActive($tenant, Algorithms::rs256());

        // Then
        static::assertSame('mmm-newest', $active?->kid);
    }

    #[Test]
    public function thePublishedKeysComeInCreationOrder(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->saveThreeKeys($tenant);

        // When
        $published = $this->repository->findInService($tenant);

        // Then
        static::assertSame(['zzz-oldest', 'mmm-newest', 'bbb-staged'], array_map(static fn (TenantKey $key): string => $key->kid, $published));
    }

    #[Test]
    public function anEmptyOrMissingStorageHasNoKey(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When / Then
        static::assertNull($this->repository->find($tenant, 'unknown'));
        static::assertNull($this->repository->findActive($tenant, Algorithms::rs256()));
        static::assertSame([], $this->repository->findInService($tenant));
    }

    #[Test]
    public function readingCreatesNoStorage(): void
    {
        // When
        $this->repository->findInService(Fixtures::tenant());

        // Then
        static::assertDirectoryDoesNotExist($this->directory);
    }

    #[Test]
    public function keysAreScopedByTenant(): void
    {
        // Given
        $acme = Fixtures::tenant();
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository->save(self::key($other, Keys::pair()->kid));

        // When / Then
        static::assertNull($this->repository->find($acme, Keys::pair()->kid));
        static::assertNull($this->repository->findActive($acme, Algorithms::rs256()));
        static::assertSame([], $this->repository->findInService($acme));
        static::assertNotNull($this->repository->find($other, Keys::pair()->kid));
    }

    /**
     * A file under the slug of one tenant that names another is a storage fault, not a key of either.
     */
    #[Test]
    public function aFileOfAnotherTenantUnderTheSameSlugIsRefused(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $impostor = Fixtures::tenant('acme', 'https://id.impostor.example');
        $this->repository->save(self::key($impostor, Keys::pair()->kid));

        // Then
        $this->expectException(RuntimeException::class);

        // When
        $this->repository->find($tenant, Keys::pair()->kid);
    }

    /**
     * A key file whose algorithm the provider is no longer wired with is a storage fault, not a missing
     * key: the provider cannot sign with it and cannot say what its "alg" means (issue #156).
     */
    #[Test]
    public function aKeyOfAnAlgorithmTheProviderIsNotWiredWithIsRefused(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(self::key($tenant, Keys::pair()->kid));
        $unwired = new FileTenantKeyRepository($this->directory, new JoseSignatureAlgorithms([Algorithms::es256()]));

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('names an algorithm this provider is not wired with');

        // When
        $unwired->find($tenant, Keys::pair()->kid);
    }

    /**
     * Spec/saml.md section 5.1: the key of a capability the deployment turned off after the tenant drew it is read
     * past, and the keys beside it are read as they were.
     */
    #[Test]
    public function theKeyOfADormantAlgorithmIsReadPast(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(self::activeKey($tenant, Keys::pair()->kid));
        $this->repository->save(self::applicationServerKey($tenant));

        // When
        $keys = $this->withoutApplicationServer()->findAll($tenant);

        // Then
        static::assertSame([Keys::pair()->kid], array_map(static fn (TenantKey $key): string => $key->kid, $keys));
    }

    /**
     * Spec/saml.md section 5.1: nothing answers for the key of a dormant algorithm, its kid included.
     */
    #[Test]
    public function theKeyOfADormantAlgorithmIsNotFoundByItsKid(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(self::applicationServerKey($tenant));

        // When / Then
        static::assertNull($this->withoutApplicationServer()->find($tenant, Keys::applicationServerPair()->kid));
    }

    /**
     * Spec/saml.md section 5.1: a key read past while its capability was off is in service again, as it was, once
     * its algorithm is wired again.
     */
    #[Test]
    public function aKeyReadPastIsInServiceAgainOnceItsAlgorithmIsWired(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(self::applicationServerKey($tenant));
        $this->withoutApplicationServer()->findAll($tenant);

        // When
        $inService = new FileTenantKeyRepository($this->directory, Algorithms::everyUse())->findInService($tenant);

        // Then
        static::assertSame(
            [[Keys::applicationServerPair()->kid, KeyStatus::Active]],
            array_map(static fn (TenantKey $key): array => [$key->kid, $key->status], $inService),
        );
    }

    /**
     * Spec/saml.md section 5.1, issue #156: a name that neither the wiring nor a section that left its capability
     * off knows is still a fault of the storage.
     */
    #[Test]
    public function aKeyOfAnAlgorithmNoSectionLeftOffIsStillRefused(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(self::key($tenant, Keys::pair()->kid));
        $unwired = new FileTenantKeyRepository(
            $this->directory,
            new JoseSignatureAlgorithms([Algorithms::es256()]),
            new DormantKeyAlgorithms([Algorithms::vapid()]),
        );

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('names an algorithm this provider is not wired with');

        // When
        $unwired->findAll($tenant);
    }

    /**
     * Spec/saml.md S-64: the key of an upstream identity provider nothing wires any more, an algorithm of a family named
     * after its holder, is read past, and the keys beside it are read as they were.
     */
    #[Test]
    public function theKeyOfAProviderNothingWiresIsReadPast(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(self::activeKey($tenant, Keys::pair()->kid));
        $wired = new FileTenantKeyRepository($this->directory, self::withProviders(['https://idp-a.example/metadata']));
        $wired->save(self::providerKey($tenant, 'https://idp-a.example/metadata'));
        $unwired = new FileTenantKeyRepository(
            $this->directory,
            Algorithms::all(),
            new DormantKeyAlgorithms([], [SamlEncryptionAlgorithmInterface::NAME_PREFIX]),
        );

        // When
        $keys = $unwired->findAll($tenant);

        // Then
        static::assertSame([Keys::pair()->kid], array_map(static fn (TenantKey $key): string => $key->kid, $keys));
    }

    /**
     * Spec/saml.md S-64: one material is the key of one algorithm, so the key of another algorithm under the "kid" a
     * file holds is refused rather than written over it, and the key that file holds is left as it was.
     */
    #[Test]
    public function theKeyOfAnotherAlgorithmUnderAKidHeldAlreadyIsRefused(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $repository = new FileTenantKeyRepository($this->directory, self::withProviders(['https://idp-a.example/metadata', 'https://idp-b.example/metadata']));
        $repository->save(self::providerKey($tenant, 'https://idp-a.example/metadata'));

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The key "%s" of tenant "acme" is held already, and not as a key of SAML-ENCRYPTION:https://idp-b.example/metadata: one material is the key of one algorithm.',
            Keys::otherPair()->kid,
        ));

        // When
        $repository->save(self::providerKey($tenant, 'https://idp-b.example/metadata'));
    }

    /**
     * The key a file holds is saved again as it changes, under the same algorithm: its status survives.
     */
    #[Test]
    public function aKeyIsSavedAgainUnderItsOwnAlgorithm(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $key = self::key($tenant, Keys::pair()->kid);
        $this->repository->save($key);
        $key->activate(Fixtures::now());

        // When
        $this->repository->save($key);

        // Then
        static::assertSame(KeyStatus::Active, $this->repository->find($tenant, Keys::pair()->kid)?->status);
    }

    #[Test]
    #[DataProvider('provideKidsThatCannotNameAFile')]
    public function aKidThatIsNotAThumbprintNamesNoFile(string $kid): void
    {
        // When / Then
        static::assertNull($this->repository->find(Fixtures::tenant(), $kid));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideKidsThatCannotNameAFile(): iterable
    {
        yield 'a path' => ['../../etc/passwd'];
        yield 'a slash' => ['a/b'];
        yield 'a dot' => ['.'];
        yield 'empty' => [''];
        yield 'a space' => ['a b'];
    }

    #[Test]
    public function aKeyWhoseKidCannotNameAFileIsNotSaved(): void
    {
        // Given
        $key = new TenantKey(
            '../escape',
            Fixtures::tenant(),
            Algorithms::rs256(),
            [
                'kid' => '../escape',
            ] + Keys::pair()->publicJwk,
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );

        // Then
        $this->expectException(RuntimeException::class);

        // When
        $this->repository->save($key);
    }

    #[Test]
    #[DataProvider('provideCorruptedDocuments')]
    public function aFileThatIsNotATenantKeyDocumentIsAFault(string $content): void
    {
        // Given
        mkdir($this->directory . '/acme', 0o700, true);
        file_put_contents($this->directory . '/acme/' . Keys::pair()->kid . '.json', $content);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        $this->repository->findInService(Fixtures::tenant());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCorruptedDocuments(): iterable
    {
        yield 'not JSON' => ['{'];
        yield 'not an object' => ['[]'];
        yield 'no kid' => [json_encode([
            'algorithm' => 'RS256',
        ], JSON_THROW_ON_ERROR)];
        yield 'an unknown algorithm' => [json_encode(self::document([
            'algorithm' => 'HS256',
        ]), JSON_THROW_ON_ERROR)];
        yield 'an unknown status' => [json_encode(self::document([
            'status' => 'lost',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a sealed key that is not base64' => [json_encode(self::document([
            'sealed_private_jwk' => '***',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a public JWK that is not a map of strings' => [json_encode(self::document([
            'public_jwk' => [
                'kid' => 1,
            ],
        ]), JSON_THROW_ON_ERROR)];
        yield 'a public JWK missing its members' => [json_encode(self::document([
            'public_jwk' => [
                'kid' => 'x',
            ],
        ]), JSON_THROW_ON_ERROR)];
        yield 'a date that is not RFC 3339' => [json_encode(self::document([
            'created_at' => 'yesterday',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a key without its activation due date' => [json_encode(self::document([
            'activation_due_at' => null,
        ]), JSON_THROW_ON_ERROR)];
        yield 'an active key without its activation date' => [json_encode(self::document([
            'activated_at' => null,
        ]), JSON_THROW_ON_ERROR)];
        yield 'a retiring key without its date' => [json_encode(self::document([
            'status' => 'retiring',
            'retirement_due_at' => '2026-09-15T10:20:00.000+00:00',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a retiring key without its retirement date' => [json_encode(self::document([
            'status' => 'retiring',
            'retiring_at' => '2026-09-15T10:10:00.000+00:00',
        ]), JSON_THROW_ON_ERROR)];
        yield 'a retired key without its date' => [json_encode(self::document([
            'status' => 'retired',
            'retiring_at' => '2026-09-15T10:10:00.000+00:00',
            'retirement_due_at' => '2026-09-15T10:20:00.000+00:00',
        ]), JSON_THROW_ON_ERROR)];
    }

    #[Test]
    public function theStorageIsPrivateToTheProcessOwner(): void
    {
        // When
        $this->repository->save(self::key(Fixtures::tenant(), Keys::pair()->kid));

        // Then
        static::assertSame('700', decoct(fileperms($this->directory . '/acme') & 0o777));
        static::assertSame('600', decoct(fileperms($this->directory . '/acme/' . Keys::pair()->kid . '.json') & 0o777));
    }

    /**
     * The proof of custody of issue #57, on the files: whatever the KMS, a key file carries the public JWK
     * in clear and the private one sealed, so no private member of RFC 7518 §6.3.2 appears in it, nor the
     * private members themselves as the sealer received them.
     */
    #[Test]
    public function noKeyFileCarriesAPrivateMemberInClear(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->repository->save(
            new TenantKey(
                Keys::pair()->kid,
                $tenant,
                Algorithms::rs256(),
                Keys::pair()->publicJwk,
                Keys::sealer()->seal($tenant, Keys::pair()->privateJwk),
                Fixtures::now(),
                Fixtures::now(),
            ),
        );

        // When
        $files = glob($this->directory . '/*/*.json');

        // Then
        static::assertIsArray($files);
        static::assertCount(1, $files);
        foreach ($files as $file) {
            $document = (string) file_get_contents($file);
            foreach (['d', 'p', 'q', 'dp', 'dq', 'qi'] as $member) {
                static::assertStringNotContainsString(sprintf('"%s":', $member), $document);
                static::assertStringNotContainsString(Keys::pair()->privateJwk[$member], $document);
            }
        }
    }

    #[Test]
    public function savingLeavesNoTemporaryFile(): void
    {
        // When
        $this->repository->save(self::key(Fixtures::tenant(), Keys::pair()->kid));

        // Then
        static::assertSame([$this->directory . '/acme/' . Keys::pair()->kid . '.json'], glob($this->directory . '/acme/*'));
    }

    #[Test]
    public function aStorageThatCannotBeCreatedIsAFault(): void
    {
        // Given
        file_put_contents($this->directory, 'a file where the directory should be');
        $key = self::key(Fixtures::tenant(), Keys::pair()->kid);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        $this->repository->save($key);
    }

    /**
     * Four keys saved out of creation order: the oldest retiring, the middle one retired, the newest active,
     * one staged after it.
     */
    private function saveThreeKeys(Tenant $tenant): void
    {
        $oldest = self::activeKey($tenant, 'zzz-oldest', Fixtures::now()->modify('-2 days'));
        $oldest->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $middle = self::activeKey($tenant, 'aaa-middle', Fixtures::now()->modify('-1 day'));
        $middle->startRetiring(Fixtures::now(), Fixtures::now());
        $middle->retire(Fixtures::now());
        $newest = self::activeKey($tenant, 'mmm-newest', Fixtures::now());
        $staged = self::key($tenant, 'bbb-staged', Fixtures::now()->modify('+1 minute'));
        $this->repository->save($newest);
        $this->repository->save($staged);
        $this->repository->save($oldest);
        $this->repository->save($middle);
    }

    /**
     * The document as written, with what the test wants wrong.
     *
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function document(array $overrides): array
    {
        return $overrides
        + [
            'kid' => Keys::pair()->kid,
            'tenant_id' => 'ignored: the tenant check comes after the shape check',
            'algorithm' => 'RS256',
            'public_jwk' => Keys::pair()->publicJwk,
            'sealed_private_jwk' => base64_encode('sealed'),
            'status' => 'active',
            'created_at' => '2026-09-15T10:00:00.000+00:00',
            'activation_due_at' => '2026-09-15T10:06:00.000+00:00',
            'activated_at' => '2026-09-15T10:06:00.000+00:00',
            'retiring_at' => null,
            'retirement_due_at' => null,
            'retired_at' => null,
        ];
    }

    private static function key(Tenant $tenant, string $kid, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        return new TenantKey(
            $kid,
            $tenant,
            Algorithms::rs256(),
            [
                'kid' => $kid,
            ] + Keys::pair()->publicJwk,
            'sealed',
            $createdAt ?? Fixtures::now(),
            $createdAt ?? Fixtures::now(),
        );
    }

    /**
     * The algorithms of the suite and the one of each upstream identity provider given (spec/saml.md S-64).
     *
     * @param list<string> $providers
     */
    private static function withProviders(array $providers): JoseKeyAlgorithms
    {
        $algorithms = [];
        foreach ($providers as $provider) {
            $algorithms[] = new SamlEncryption($provider);
        }
        $schedule = new RotationSchedule(new DateInterval('PT6M'), new DateInterval('P90D'));

        return new JoseKeyAlgorithms([
            new JoseKeyFamily(Algorithms::all(), $schedule),
            new JoseKeyFamily(new JoseSamlEncryptionAlgorithms($algorithms), $schedule),
        ]);
    }

    /**
     * The key an upstream identity provider encrypts for, on the second RSA pair of the suite.
     */
    private static function providerKey(Tenant $tenant, string $provider): TenantKey
    {
        $algorithm = new SamlEncryption($provider);
        $pair = Keys::otherPair();

        return new TenantKey(
            $pair->kid,
            $tenant,
            $algorithm,
            [
                ...$pair->publicJwk,
                'alg' => $algorithm->name(),
                'use' => $algorithm->keyUse()->value,
            ],
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );
    }

    private static function activeKey(Tenant $tenant, string $kid, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        $key = self::key($tenant, $kid, $createdAt);
        $key->activate(Fixtures::now());

        return $key;
    }

    /**
     * The application server key of the tenant, active: the key of a capability a deployment may turn off.
     */
    private static function applicationServerKey(Tenant $tenant): TenantKey
    {
        $pair = Keys::applicationServerPair();
        $key = new TenantKey($pair->kid, $tenant, Algorithms::vapid(), $pair->publicJwk, 'sealed', Fixtures::now(), Fixtures::now());
        $key->activate(Fixtures::now());

        return $key;
    }

    /**
     * The same storage read by a deployment that reaches nobody by push: the signature algorithms wired, the
     * application server algorithm dormant.
     */
    private function withoutApplicationServer(): FileTenantKeyRepository
    {
        return new FileTenantKeyRepository($this->directory, Algorithms::all(), new DormantKeyAlgorithms([Algorithms::vapid()]));
    }
}
