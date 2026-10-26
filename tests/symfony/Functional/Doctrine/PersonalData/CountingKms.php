<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

use SensitiveParameter;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKey;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;
use Symfony\Component\KeyManagement\DecrypterInterface;
use Symfony\Component\KeyManagement\EncrypterInterface;

/**
 * The KMS of the test kernel, counting what it is asked (`config_test.yml` decorates the client the
 * configuration names with it).
 *
 * The third success criterion of the spike is a count, not a duration, and it is read in the log of the
 * KMS when it is measured against a running stack ("castor login-cost"). What a test needs is the same
 * count where there is no KMS on a network: one unwrap per data key and per process, and none per value.
 * It counts and nothing else, every call going to the client of the kernel whatever the backend.
 */
final class CountingKms implements DataKeyGeneratorInterface, DecrypterInterface, EncrypterInterface
{
    /**
     * @var int how many data keys were minted, which is one per scope that had none
     */
    public int $minted = 0;

    /**
     * @var int how many wrapped data keys were opened, which is what a store does once per key and per
     *          process
     */
    public int $unwrapped = 0;

    public function __construct(
        private readonly DataKeyGeneratorInterface&DecrypterInterface&EncrypterInterface $kms,
    ) {
    }

    public function forget(): void
    {
        $this->minted = 0;
        $this->unwrapped = 0;
    }

    public function generateDataKey(string $keyId, int $length = 32, string $aad = ''): DataKey
    {
        ++$this->minted;

        return $this->kms->generateDataKey($keyId, $length, $aad);
    }

    public function unwrapDataKey(Ciphertext $wrapped, string $aad = ''): DataKey
    {
        ++$this->unwrapped;

        return $this->kms->unwrapDataKey($wrapped, $aad);
    }

    public function encrypt(string $keyId, #[SensitiveParameter] string $plaintext, string $aad = ''): Ciphertext
    {
        return $this->kms->encrypt($keyId, $plaintext, $aad);
    }

    public function decrypt(Ciphertext $ciphertext, string $aad = ''): string
    {
        return $this->kms->decrypt($ciphertext, $aad);
    }
}
