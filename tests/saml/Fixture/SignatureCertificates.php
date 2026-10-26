<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function array_map;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * What the KeyInfo of each signature of a document carries (spec/saml.md S-37), read as a peer that wants the hint
 * reads it: the X509Certificate elements of its one X509Data.
 */
final readonly class SignatureCertificates
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * @return list<list<string>> for each ds:Signature of the document, in document order, the text of each
     *                            X509Certificate of its KeyInfo
     */
    public static function of(Document $document): array
    {
        $certificates = [];
        foreach ($document->root()->getElementsByTagNameNS(self::DSIG, 'Signature') as $signature) {
            $data = Children::one(Children::one($signature, new Name(self::DSIG, 'KeyInfo')), new Name(self::DSIG, 'X509Data'));
            $certificates[] = array_map(
                static fn (Element $certificate): string => (string) $certificate->textContent,
                Children::named($data, new Name(self::DSIG, 'X509Certificate')),
            );
        }

        return $certificates;
    }
}
