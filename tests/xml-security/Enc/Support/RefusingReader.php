<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MissingChild;
use Beffroi\Xml\Enc\PlaintextReaderInterface;

/**
 * A reading of section 5.2 that refuses every plaintext, as a consumer refuses a schema, a signature or an issuer
 * (E-16), and records that it was asked.
 *
 * @implements PlaintextReaderInterface<Document>
 */
final class RefusingReader implements PlaintextReaderInterface
{
    public bool $asked = false;

    public function read(Document $plaintext): Document
    {
        $this->asked = true;

        throw new MissingChild('The consumer refuses what the plaintext holds (E-16).');
    }
}
