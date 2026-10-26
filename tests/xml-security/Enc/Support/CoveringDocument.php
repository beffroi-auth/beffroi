<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Enc\CoveringSignatureInterface;

/**
 * The proof of section 5.2 built by a test: a document the test says a verified signature covers. Enc checks what the
 * proof covers, never where it comes from (E-15), so that a test needs no signature to reach AES-CBC; the consumer's
 * proof, saml2-model's, is built from a verification of Dsig.
 */
final readonly class CoveringDocument implements CoveringSignatureInterface
{
    public function __construct(
        private Document $document,
    ) {
    }

    public function document(): Document
    {
        return $this->document;
    }
}
