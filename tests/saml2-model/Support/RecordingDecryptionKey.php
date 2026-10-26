<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Support;

use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\OaepHash;

/**
 * The service provider's key of section 5.5, which records whether it was asked to unwrap anything: what proves that
 * a refusal came before any key was touched (section 6.7, enc.md E-15).
 */
final class RecordingDecryptionKey implements DecryptionKeyInterface
{
    public bool $asked = false;

    public function __construct(
        private readonly DecryptionKeyInterface $key,
    ) {
    }

    public function unwrap(string $wrapped, OaepHash $hash): ?string
    {
        $this->asked = true;

        return $this->key->unwrap($wrapped, $hash);
    }
}
