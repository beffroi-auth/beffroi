<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Bridge\JwtLibrary\Algorithm\A256Gcm;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\EcdhEsA256Kw;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\EdDsa;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Es256;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\MessageSeal;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Ps256;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Rs256;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaOaep256;
use Beffroi\Core\Bridge\JwtLibrary\JoseContentEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Vapid;
use Beffroi\Core\Bridge\JwtLibrary\JoseApplicationServerAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseAlgorithmRegistryInterface;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithms;
use function array_map;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyFamily;
use Beffroi\Core\Domain\Key\RotationSchedule;
use DateInterval;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseMessageSealingAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;

/**
 * The algorithms of the suite, wired as the bundle wires them, RS256 first and the two a client encrypts
 * to beside them. RSA keys are 2048 bits here: generation is what makes a test slow, and 2048 is what
 * RFC 7518 §3.3 asks for.
 */
final class Algorithms
{
    private static ?Rs256 $rs256 = null;

    private static ?Ps256 $ps256 = null;

    private static ?Es256 $es256 = null;

    private static ?EdDsa $edDsa = null;

    private static ?EcdhEsA256Kw $ecdhEsA256Kw = null;

    private static ?RsaOaep256 $rsaOaep256 = null;

    private static ?A256Gcm $a256Gcm = null;

    private static ?JoseSignatureAlgorithms $all = null;

    private static ?JoseKeyEncryptionAlgorithms $keyEncryption = null;

    private static ?JoseContentEncryptionAlgorithms $contentEncryption = null;

    private static ?Vapid $vapid = null;

    private static ?JoseApplicationServerAlgorithms $applicationServer = null;

    private static ?MessageSeal $messageSeal = null;

    private static ?JoseMessageSealingAlgorithms $messageSealing = null;

    private static ?JoseKeyAlgorithms $everyUse = null;

    private static ?JoseEncryptionAlgorithms $encryption = null;

    public static function rs256(): Rs256
    {
        return self::$rs256 ??= new Rs256(new RsaKeyBits(2048));
    }

    public static function ps256(): Ps256
    {
        return self::$ps256 ??= new Ps256(new RsaKeyBits(2048));
    }

    public static function es256(): Es256
    {
        return self::$es256 ??= new Es256();
    }

    public static function edDsa(): EdDsa
    {
        return self::$edDsa ??= new EdDsa();
    }

    public static function ecdhEsA256Kw(): EcdhEsA256Kw
    {
        return self::$ecdhEsA256Kw ??= new EcdhEsA256Kw();
    }

    public static function rsaOaep256(): RsaOaep256
    {
        return self::$rsaOaep256 ??= new RsaOaep256(new RsaKeyBits(2048));
    }

    public static function a256Gcm(): A256Gcm
    {
        return self::$a256Gcm ??= new A256Gcm();
    }

    public static function all(): JoseSignatureAlgorithms
    {
        return self::$all ??= new JoseSignatureAlgorithms([self::rs256(), self::ps256(), self::es256(), self::edDsa()]);
    }

    public static function keyEncryption(): JoseKeyEncryptionAlgorithms
    {
        return self::$keyEncryption ??= new JoseKeyEncryptionAlgorithms([self::ecdhEsA256Kw(), self::rsaOaep256()]);
    }

    public static function contentEncryption(): JoseContentEncryptionAlgorithms
    {
        return self::$contentEncryption ??= new JoseContentEncryptionAlgorithms([self::a256Gcm()]);
    }

    /**
     * A deployment nobody encrypts to: the lists the wiring leaves empty.
     */
    public static function noKeyEncryption(): JoseKeyEncryptionAlgorithms
    {
        return new JoseKeyEncryptionAlgorithms([]);
    }

    public static function noContentEncryption(): JoseContentEncryptionAlgorithms
    {
        return new JoseContentEncryptionAlgorithms([]);
    }

    /**
     * What a JWE is made and opened with, the two lists of one use read as one.
     */
    public static function encryption(): JoseEncryptionAlgorithms
    {
        return self::$encryption ??= new JoseEncryptionAlgorithms(self::keyEncryption(), self::contentEncryption());
    }

    public static function vapid(): Vapid
    {
        return self::$vapid ??= new Vapid();
    }

    /**
     * A deployment that hands out no key of its own, which is the default (§5.6).
     */
    public static function noApplicationServer(): JoseApplicationServerAlgorithms
    {
        return new JoseApplicationServerAlgorithms([]);
    }

    /**
     * The algorithms of the keys a tenant hands out itself (RFC 8292 §2).
     */
    public static function applicationServer(): JoseApplicationServerAlgorithms
    {
        return self::$applicationServer ??= new JoseApplicationServerAlgorithms([self::vapid()]);
    }

    /**
     * The algorithm of the key a tenant seals what leaves the process to (decision 0020).
     */
    public static function messageSeal(): MessageSeal
    {
        return self::$messageSeal ??= new MessageSeal(self::ecdhEsA256Kw(), self::a256Gcm());
    }

    public static function messageSealing(): JoseMessageSealingAlgorithms
    {
        return self::$messageSealing ??= new JoseMessageSealingAlgorithms([self::messageSeal()]);
    }

    /**
     * A deployment wired with nothing to seal a message body to, which writes no message.
     */
    public static function noMessageSealing(): JoseMessageSealingAlgorithms
    {
        return new JoseMessageSealingAlgorithms([]);
    }

    /**
     * Every algorithm a key may be generated for, the lists of one use read as one.
     */
    public static function everyUse(): JoseKeyAlgorithms
    {
        return self::$everyUse ??= self::readAsOne([
            self::all(),
            self::keyEncryption(),
            self::applicationServer(),
            self::messageSealing(),
        ]);
    }

    /**
     * The registries given read as one, each a family of keys rotating by the staging delay and the age of
     * KeyLifecycle.
     *
     * @param non-empty-list<JoseAlgorithmRegistryInterface> $registries
     */
    public static function readAsOne(array $registries): JoseKeyAlgorithms
    {
        $schedule = new RotationSchedule(new DateInterval(KeyLifecycle::STAGING_DELAY), new DateInterval(KeyLifecycle::AGE));

        return new JoseKeyAlgorithms(array_map(
            static fn (JoseAlgorithmRegistryInterface $registry): JoseKeyFamily => new JoseKeyFamily($registry, $schedule),
            $registries,
        ));
    }
}
