<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Key;

use function array_map;
use function base64_decode;
use DateInterval;
use function explode;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Tests\Fixture\FixedRotationSchedules;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Application\Key\NamedKey;
use Beffroi\Core\Application\Key\RetirementWindow;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\JwsSignerInterface;
use Beffroi\Core\Port\KeyPairGeneratorInterface;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\PublicKeySetProviderInterface;
use Beffroi\Core\Port\SigningKeyProviderInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use function strtr;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Architecture §3.3: the provider the kernel holds is one object for the life of the process, which in
 * a FrankenPHP worker is every request the worker serves. A rotation is done by another process, a
 * console command or a scheduled step, that shares nothing with the worker but the key files. The
 * worker must see it without a restart: the provider reads which key is active on each call and keeps
 * only the opened material, by "kid". Proven here with a second repository on the same directory, as
 * another process would have; the kernel is not rebooted between the steps.
 */
final class SealedKeyProviderTest extends DatabaseTestCase
{
    private string $directory;

    private SigningKeyProviderInterface $provider;

    private PublicKeySetProviderInterface $published;

    private OpenedKeys $opened;

    protected function setUp(): void
    {
        parent::setUp();
        $cacheDir = self::getContainer()->getParameter('kernel.cache_dir');
        static::assertIsString($cacheDir);
        $this->directory = $cacheDir . '/keys';
        new Filesystem()->remove($this->directory);
        $this->provider = self::service('test.beffroi.key_provider', SigningKeyProviderInterface::class);
        $this->published = self::service('test.beffroi.public_keys', PublicKeySetProviderInterface::class);
        $this->opened = self::service('test.beffroi.opened_keys', OpenedKeys::class);
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        new Filesystem()->remove($this->directory);
    }

    /**
     * The key that signs is the one another process activated, seen by the provider that had already
     * opened the previous one.
     */
    #[Test]
    public function aRotationDoneByAnotherProcessIsSeenWithoutARestart(): void
    {
        // Given
        $opened = $this->provider->activeKey(self::tenant(), Algorithms::rs256());
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $active = $this->provider->activeKey(self::tenant(), Algorithms::rs256());

        // Then
        static::assertNotSame($opened->key->kid, $rotated->kid);
        static::assertSame($rotated->kid, $active->key->kid);
    }

    /**
     * What the worker signs after the rotation names the new key, through the signer the modules use.
     */
    #[Test]
    public function theWorkerSignsWithTheNewKeyAtOnce(): void
    {
        // Given
        $signer = self::service('test.beffroi.jws_signer', JwsSignerInterface::class);
        $signer->sign(self::tenant(), Algorithms::rs256(), 'before');
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $jws = $signer->sign(self::tenant(), Algorithms::rs256(), 'after');

        // Then
        static::assertStringContainsString($rotated->kid, self::header($jws));
    }

    /**
     * The JWK Set the worker serves after the rotation carries both keys, the retiring one and the new
     * one, without a restart.
     */
    #[Test]
    public function theWorkerPublishesBothKeysAtOnce(): void
    {
        // Given
        $previous = $this->provider->activeKey(self::tenant(), Algorithms::rs256())->key;
        $rotated = $this->rotateFromAnotherProcess();

        // When
        $published = $this->published->publicKeys(self::tenant());

        // Then
        static::assertSame([$previous->kid, $rotated->kid], array_map(static fn (TenantKey $key): string => $key->kid, $published->keys));
    }

    /**
     * The provider keeps the opened material of the key that signs and no other: the previous one is
     * out of the memory of the worker once the rotation is seen.
     */
    #[Test]
    public function theWorkerForgetsThePreviousKeyOnceTheRotationIsSeen(): void
    {
        // Given
        $previous = $this->provider->activeKey(self::tenant(), Algorithms::rs256());
        $this->rotateFromAnotherProcess();

        // When
        $this->provider->activeKey(self::tenant(), Algorithms::rs256());

        // Then
        static::assertNotSame($previous, $this->opened->open(self::tenant(), $previous->key));
    }

    /**
     * A rotation as a console command does it: a repository of its own on the same files, the steps of the
     * life of a key of its own, nothing shared with the provider under test but the directory.
     */
    private function rotateFromAnotherProcess(): TenantKey
    {
        $keys = new FileTenantKeyRepository($this->directory, Algorithms::all());
        $named = new NamedKey($keys);
        $clock = new NativeClock();
        $events = new RecordingEventDispatcher();
        $staging = new KeyStaging(
            $keys,
            self::service('test.beffroi.key_pair_generator', KeyPairGeneratorInterface::class),
            self::service('test.beffroi.key_sealer', KeySealerInterface::class),
            new FixedRotationSchedules(new RotationSchedule(new DateInterval('PT6M'), new DateInterval('P90D'))),
            $clock,
            $events,
        );

        return new KeyTakeOver(
            $keys,
            $named,
            $staging,
            new RetirementWindow([]),
            new KeyRetirement($keys, $named, $clock, $events),
            $clock,
            $events,
        )->rotate(self::tenant(), Algorithms::rs256(), self::context());
    }

    /**
     * The protected header of a compact JWS, decoded.
     */
    private static function header(string $compactJws): string
    {
        $decoded = base64_decode(strtr(explode('.', $compactJws)[0], '-_', '+/'), true);
        static::assertIsString($decoded);

        return $decoded;
    }
}
