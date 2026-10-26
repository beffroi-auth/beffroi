<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Enc\PlaintextReaderInterface;

/**
 * The reading of section 5.2 that reads nothing: the plaintext as Core loaded it is what decryptCovered() answers, as
 * decrypt() answers it.
 *
 * @implements PlaintextReaderInterface<Document>
 */
final readonly class LoadedDocument implements PlaintextReaderInterface
{
    public function read(Document $plaintext): Document
    {
        return $plaintext;
    }
}
