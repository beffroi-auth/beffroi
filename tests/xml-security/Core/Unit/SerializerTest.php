<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit;

use function basename;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\SerializationFailed;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Foreign;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use Dom\XMLDocument;
use function filesize;
use function glob;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function sort;
use function str_ends_with;
use function substr;

/**
 * Section 6.5, I-15: the whole document, formatOutput false, an XML declaration and UTF-8, whitespace kept, nothing
 * reformatted afterwards, the four shapes that would not survive saveXml() then a parser refused first, and so are the
 * shapes no parser accepts.
 */
final class SerializerTest extends TestCase
{
    /** Where a built document can hold a string a consumer chose: what saveXml() writes as it is (section 13). */
    private const array PLACES = [
        'text',
        'CDATA section',
        'comment',
        'processing instruction',
        'attribute value',
        'namespace name',
    ];

    private Serializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new Serializer();
    }

    /**
     * §9.3 row 16: the declaration on the first line, the root with its namespace declaration on the second, no
     * indentation.
     */
    #[Test]
    public function itSerializesACreatedDocumentWithTheDeclarationThenTheRoot(): void
    {
        // Given
        $document = new DocumentFactory()->create(
            new Name('urn:oasis:names:tc:SAML:2.0:protocol', 'AuthnRequest'),
            'samlp',
        );
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:Issuer',
        ))->appendChild($xml->createTextNode('https://sp.example.org'));

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.org</saml:Issuer>'
            . '</samlp:AuthnRequest>',
            $bytes,
        );
    }

    /**
     * §9.3 row 11, I-15: a loaded document with whitespace between elements, serialized, is the same bytes, the
     * declaration aside and the line feed after the root aside, which the parser never kept.
     */
    #[Test]
    public function itSerializesALoadedDocumentByteForByteDeclarationAside(): void
    {
        // Given
        $bytes = Fixtures::bytes('behaviour/response-with-assertion.xml');
        $document = Loaded::document($bytes);

        // When
        $serialized = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" . substr($bytes, 0, -1), $serialized);
    }

    /**
     * I-15: formatOutput stays false, whatever a consumer set on the Dom\XMLDocument it can reach.
     */
    #[Test]
    public function itNeverPrettyPrints(): void
    {
        // Given
        $document = Loaded::document('<a><b/></a>');
        $xml = $document->root()->ownerDocument;
        static::assertInstanceOf(XMLDocument::class, $xml);
        $xml->formatOutput = true;

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a><b/></a>", $bytes);
    }

    /**
     * §9.2 row 26, I-4: a Document built by hand around a document parsed outside the loader.
     */
    #[Test]
    public function itRefusesADocumentTheBrickDidNotProduce(): void
    {
        // Given
        $root = Foreign::parse('<a/>')->documentElement;
        static::assertNotNull($root);
        $document = new Document($root, []);

        // Then
        $this->expectException(ForeignNode::class);
        $this->expectExceptionMessageIs('The document is not one the brick produced (I-4).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * §9.3 row 17: every serialized document of the fixtures is either refused by a rule of section 6.5, or loads
     * again through the Loader without refusal and canonicalizes to the same bytes as before serialization. What
     * the serializer lets out is the canonical form that was signed.
     */
    #[Test]
    #[DataProvider('provideLoadableFixtures')]
    public function itsOutputLoadsAgainAndCanonicalizesToTheSameBytesUnlessItRefuses(string $fixture): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = Loaded::fixture($fixture);
        $before = $canonicalizer->canonicalize($document->root(), CanonicalizationMethod::InclusiveWithComments)->bytes;

        // When
        try {
            $serialized = $this->serializer->serialize($document);
        } catch (SerializationFailed $refused) {
            static::assertStringEndsWith('(section 6.5).', $refused->getMessage());

            return;
        }

        // Then
        $reloaded = Loaded::document($serialized);
        static::assertSame(
            $before,
            $canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::InclusiveWithComments)->bytes,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLoadableFixtures(): iterable
    {
        $paths = [];
        foreach (['canonical', 'behaviour', 'real', 'hostile'] as $directory) {
            $found = glob(__DIR__ . '/../Fixture/' . $directory . '/*.xml');
            if ($found === false) {
                throw new RuntimeException('The fixtures cannot be listed.');
            }
            foreach ($found as $path) {
                $name = basename($path);
                if ($directory === 'hostile' && ! str_ends_with($name, '-loads.xml')) {
                    continue;
                }
                // 512 declarations over 10 000 elements: seconds of inclusive canonicalization (section 13),
                // round-tripped exclusively in its own test
                if ($name === 'at-the-six-default-bounds-loads.xml') {
                    continue;
                }
                // at the byte bound: the declaration the serializer adds pushes them over maxBytes on the way back
                if (filesize($path) > (1_048_576 - 40)) {
                    continue;
                }
                $paths[] = $directory . '/' . $name;
            }
        }
        sort($paths);
        foreach ($paths as $path) {
            yield $path => [$path];
        }
    }

    /**
     * §9.3 row 17, section 7: the document at the six default bounds round-trips too, exclusively, since its
     * inclusive canonical form costs seconds with 512 declarations in scope over 10 000 elements (section 13).
     */
    #[Test]
    public function itsOutputOfTheDocumentAtTheSixBoundsLoadsAgainAndCanonicalizesToTheSameBytes(): void
    {
        // Given
        $canonicalizer = new Canonicalizer();
        $document = Loaded::fixture('behaviour/at-the-six-default-bounds-loads.xml');
        $before = $canonicalizer->canonicalize($document->root(), CanonicalizationMethod::Exclusive)->bytes;

        // When
        $reloaded = Loaded::document($this->serializer->serialize($document));

        // Then
        static::assertSame(
            $before,
            $canonicalizer->canonicalize($reloaded->root(), CanonicalizationMethod::Exclusive)->bytes,
        );
    }

    /**
     * §9.3 row 20, section 6.5: the four shapes measured not to survive saveXml() then a parser, each in a loaded
     * fixture, each refused with its rule named (I-16).
     */
    #[Test]
    #[DataProvider('provideShapesThatWouldNotRoundTrip')]
    public function itRefusesAShapeThatWouldNotRoundTrip(string $fixture, string $message): void
    {
        // Given
        $document = Loaded::fixture($fixture);

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideShapesThatWouldNotRoundTrip(): iterable
    {
        yield 'a carriage return in a text node, the vector of Canonical XML 1.0 §3.4' => [
            'canonical/c14n-3.4-derived-character-references.xml',
            'A text, CDATA, comment or processing instruction node holds a carriage return, which a parser would normalise to a line feed (section 6.5).',
        ];
        yield 'a prefix bound to the in-scope default namespace, the ds:KeyInfo of Entra' => [
            'real/entra-common-federation-metadata-2026-09-23.xml',
            'An element carries a prefix bound to the in-scope default namespace, which saveXml() would drop (section 6.5).',
        ];
        yield 'a CDATA section holding the end marker, two adjacent sections merged by the parser' => [
            'behaviour/adversarial-cdata-nested-marker-loads.xml',
            'A CDATA section holds the sequence that ends one, which saveXml() would write as it is (section 6.5).',
        ];
        yield 'an ampersand in a namespace name' => [
            'behaviour/adversarial-xmlns-attribute-value-with-entity-amp-loads.xml',
            'A namespace name holds an ampersand, which saveXml() does not write faithfully (section 6.5).',
        ];
    }

    /**
     * §9.3 row 20, section 6.5, measured: the namespace fix-up of saveXml() drops the prefix of an element whose
     * namespace is the default namespace in force where it starts, whichever element declared it and whatever the
     * element declares itself.
     */
    #[Test]
    #[DataProvider('provideAPrefixBoundToTheInScopeDefaultNamespace')]
    public function itRefusesAPrefixBoundToTheInScopeDefaultNamespace(string $xml): void
    {
        // Given
        $document = Loaded::document($xml);

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('An element carries a prefix bound to the in-scope default namespace, which saveXml() would drop (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAPrefixBoundToTheInScopeDefaultNamespace(): iterable
    {
        yield 'declared by the parent' => ['<a xmlns="urn:x"><p:b xmlns:p="urn:x"><p:c/></p:b></a>'];
        yield 'declared by a prefixed parent' => ['<p:a xmlns:p="urn:x" xmlns="urn:y"><q:b xmlns:q="urn:y"/></p:a>'];
        yield 'undeclared again by the element itself' => [
            '<a xmlns="urn:x"><p:b xmlns:p="urn:x" xmlns=""><c/></p:b></a>',
        ];
        yield 'declared by the element itself, for its child' => [
            '<r><p:a xmlns:p="urn:x" xmlns="urn:x"><p:b/></p:a></r>',
        ];
    }

    /**
     * §9.3 row 9, section 6.5: two prefixes bound to one namespace name are written as they are, so a second
     * prefix is not the shape saveXml() drops.
     */
    #[Test]
    public function itKeepsASecondPrefixBoundToTheSameNamespace(): void
    {
        // Given
        $document = Loaded::document('<a xmlns:q="urn:x"><p:b xmlns:p="urn:x"/></a>');

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a xmlns:q=\"urn:x\"><p:b xmlns:p=\"urn:x\"/></a>",
            $bytes,
        );
    }

    /**
     * §9.3 row 21, section 6.5, measured: a carriage return in any character data node is written as the byte
     * itself, and a parser normalises it to a line feed, in a comment or a processing instruction too.
     */
    #[Test]
    #[DataProvider('provideCharacterDataNodeTypes')]
    public function itRefusesACarriageReturnInABuiltCharacterDataNode(string $type): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild(match ($type) {
            'text' => $xml->createTextNode("a\rb"),
            'CDATA section' => $xml->createCDATASection("a\rb"),
            'comment' => $xml->createComment("a\rb"),
            default => $xml->createProcessingInstruction('pi', "a\rb"),
        });

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A text, CDATA, comment or processing instruction node holds a carriage return, which a parser would normalise to a line feed (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCharacterDataNodeTypes(): iterable
    {
        foreach (['text', 'CDATA section', 'comment', 'processing instruction'] as $type) {
            yield $type => [$type];
        }
    }

    /**
     * Section 6.5: a comment or a processing instruction outside the root is walked too.
     */
    #[Test]
    public function itRefusesACarriageReturnInACommentOutsideTheRoot(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $xml->insertBefore($xml->createComment("a\rb"), $root);

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A text, CDATA, comment or processing instruction node holds a carriage return, which a parser would normalise to a line feed (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * §9.3 row 21, section 6.5, measured: a built child without a prefix is written with its namespace declared, so
     * a prefixed grandchild in the same namespace is written without its prefix.
     */
    #[Test]
    public function itRefusesAPrefixedGrandchildUnderABuiltChildInTheSameDefaultNamespace(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:r', 'root'), 'r');
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('urn:x', 'child'))->appendChild($xml->createElementNS(
            'urn:x',
            'g:grand',
        ));

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('An element carries a prefix bound to the in-scope default namespace, which saveXml() would drop (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * §9.3 row 21, section 6.5: an ampersand in the namespace of a built element, which no declaration attribute
     * carries yet; libxml's canonical form writes it raw (measured, section 13).
     */
    #[Test]
    public function itRefusesAnAmpersandInTheNamespaceOfABuiltElement(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createElementNS('urn:x?a=1&b=2', 'x:e'));

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A namespace name holds an ampersand, which saveXml() does not write faithfully (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * Section 6.5: an ampersand in the namespace of a built attribute.
     */
    #[Test]
    public function itRefusesAnAmpersandInTheNamespaceOfABuiltAttribute(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $document->root()->setAttributeNS('urn:q?c=1&d=2', 'q:att', 'v');

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A namespace name holds an ampersand, which saveXml() does not write faithfully (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * Section 6.5: a CDATA section whose data came to hold the end marker after its creation, which
     * createCDATASection() refuses but appendData() does not.
     */
    #[Test]
    public function itRefusesABuiltCdataSectionWhoseDataHoldsTheEndMarker(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $cdata = $xml->createCDATASection('a]]');
        $root->appendChild($cdata);
        $cdata->appendData('>b');

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A CDATA section holds the sequence that ends one, which saveXml() would write as it is (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * Section 6.5: two built CDATA sections stay two, and a carriage return, a line feed or a tab in an attribute
     * value is written as a character reference, so neither is a shape the serializer refuses (measured, section 13).
     */
    #[Test]
    public function itSerializesWhatSurvivesARoundTrip(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->setAttribute('v', "1\n2\t3\r4");
        $root->appendChild($xml->createCDATASection('a]]'));
        $root->appendChild($xml->createCDATASection('>b'));

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" . '<a xmlns="urn:a" v="1&#10;2&#9;3&#13;4"><![CDATA[a]]]]><![CDATA[>b]]></a>',
            $bytes,
        );
        static::assertSame("1\n2\t3\r4", Loaded::document($bytes)->root()->getAttribute('v'));
    }

    /**
     * §9.3 row 22, section 6.5, XML 1.0 §2.2: saveXml() writes a character outside the Char production as it is,
     * wherever it sits, and no parser accepts it (measured, section 13).
     */
    #[Test]
    #[DataProvider('provideCharactersOutsideTheCharProductionInEachPlace')]
    public function itRefusesACharacterOutsideTheCharProduction(string $place, string $character): void
    {
        // Given
        $document = self::documentHolding($place, 'a' . $character . 'b');

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('The document holds a character outside the Char production of XML 1.0 §2.2, which no parser accepts (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCharactersOutsideTheCharProductionInEachPlace(): iterable
    {
        $characters = [
            'U+0001' => "\u{1}",
            'U+0008' => "\u{8}",
            'U+000B' => "\u{B}",
            'U+001F' => "\u{1F}",
            'U+FFFE' => "\u{FFFE}",
            'U+FFFF' => "\u{FFFF}",
        ];
        foreach (self::PLACES as $place) {
            foreach ($characters as $name => $character) {
                yield $name . ' in ' . $place => [$place, $character];
            }
        }
    }

    /**
     * §9.3 row 22, section 6.5, XML 1.0 §2.2: a comment outside the root is scanned too.
     */
    #[Test]
    public function itRefusesACharacterOutsideTheCharProductionOutsideTheRoot(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $xml->insertBefore($xml->createComment("a\u{1}b"), $root);

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('The document holds a character outside the Char production of XML 1.0 §2.2, which no parser accepts (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * §9.3 row 22, section 6.5, XML 1.0 §2.2: bytes that are not UTF-8, a surrogate encoded on its own among them,
     * are written as they are, wherever they sit, and no parser accepts them (measured, section 13).
     */
    #[Test]
    #[DataProvider('provideBytesThatAreNotUtf8InEachPlace')]
    public function itRefusesBytesThatAreNotUtf8(string $place, string $bytes): void
    {
        // Given
        $document = self::documentHolding($place, 'a' . $bytes . 'b');

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('The document holds bytes that are not UTF-8, which no parser accepts (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBytesThatAreNotUtf8InEachPlace(): iterable
    {
        $sequences = [
            'an overlong slash, C0 AF' => "\xC0\xAF",
            'a surrogate, ED A0 80' => "\xED\xA0\x80",
            'a lone continuation byte, 80' => "\x80",
            'a truncated sequence, E2 82' => "\xE2\x82",
        ];
        foreach (self::PLACES as $place) {
            foreach ($sequences as $name => $sequence) {
                yield $name . ' in ' . $place => [$place, $sequence];
            }
        }
    }

    /**
     * Section 6.5, XML 1.0 §2.2: the characters at each bound of the Char production are written and load again.
     */
    #[Test]
    #[DataProvider('provideCharactersAtTheBoundsOfTheCharProduction')]
    public function itSerializesACharacterAtABoundOfTheCharProduction(string $character): void
    {
        // Given
        $document = self::documentHolding('text', 'a' . $character . 'b');

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame('a' . $character . 'b', Loaded::document($bytes)->root()->textContent);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCharactersAtTheBoundsOfTheCharProduction(): iterable
    {
        yield 'U+0009' => ["\u{9}"];
        yield 'U+000A' => ["\u{A}"];
        yield 'U+0020' => ["\u{20}"];
        yield 'U+D7FF' => ["\u{D7FF}"];
        yield 'U+E000' => ["\u{E000}"];
        yield 'U+FFFD' => ["\u{FFFD}"];
        yield 'U+10000' => ["\u{10000}"];
        yield 'U+10FFFF' => ["\u{10FFFF}"];
    }

    /**
     * §9.3 row 22, section 6.5, measured: the DOM truncates a value at a NUL byte when it is set, before the brick
     * sees it, so what is serialized is what the node holds and is well-formed; the serializer accepts it.
     */
    #[Test]
    #[DataProvider('providePlaces')]
    public function itSerializesWhatTheDomKeptOfAValueHoldingANulByte(string $place): void
    {
        // Given
        $document = self::documentHolding($place, "a\0b");

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame($bytes, $this->serializer->serialize(self::documentHolding($place, 'a')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePlaces(): iterable
    {
        foreach (self::PLACES as $place) {
            yield $place => [$place];
        }
    }

    /**
     * §9.3 row 22, section 6.5, XML 1.0 §2.5: a comment holding two adjacent hyphens, or ending with one, is written
     * as it is, inside the root or outside it, and no parser accepts it.
     */
    #[Test]
    #[DataProvider('provideCommentsTheProductionForbids')]
    public function itRefusesACommentTheProductionForbids(string $data, bool $outsideTheRoot): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $comment = $xml->createComment($data);
        if ($outsideTheRoot) {
            $xml->insertBefore($comment, $root);
        } else {
            $root->appendChild($comment);
        }

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A comment holds two adjacent hyphens or ends with one, which XML 1.0 §2.5 forbids (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideCommentsTheProductionForbids(): iterable
    {
        yield 'two hyphens inside' => ['a--b', false];
        yield 'a hyphen at the end' => ['a-', false];
        yield 'a hyphen alone' => ['-', false];
        yield 'two hyphens inside, outside the root' => ['a--b', true];
        yield 'a hyphen at the end, outside the root' => ['a-', true];
    }

    /**
     * Section 6.5, XML 1.0 §2.5: a hyphen that neither follows another nor ends the comment is allowed.
     */
    #[Test]
    public function itSerializesACommentHoldingSingleHyphens(): void
    {
        // Given
        $document = self::documentHolding('comment', '-a-b');

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a xmlns=\"urn:a\"><!---a-b--></a>", $bytes);
    }

    /**
     * §9.3 row 22, section 6.5, XML 1.0 §2.6: the target xml is reserved whatever its case, and saveXml() writes it
     * as it is, inside the root or outside it.
     */
    #[Test]
    #[DataProvider('provideReservedTargets')]
    public function itRefusesAProcessingInstructionWithTheReservedTarget(string $target, bool $outsideTheRoot): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $instruction = $xml->createProcessingInstruction($target, 'a');
        if ($outsideTheRoot) {
            $xml->insertBefore($instruction, $root);
        } else {
            $root->appendChild($instruction);
        }

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A processing instruction has the target xml, which XML 1.0 §2.6 reserves (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideReservedTargets(): iterable
    {
        yield 'xml' => ['xml', false];
        yield 'XML' => ['XML', false];
        yield 'XmL' => ['XmL', false];
        yield 'xml, outside the root' => ['xml', true];
    }

    /**
     * Section 6.5, XML 1.0 §2.6: a target that only starts with xml is not the reserved one.
     */
    #[Test]
    public function itSerializesAProcessingInstructionWhoseTargetStartsWithXml(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $root->appendChild($xml->createProcessingInstruction('xml-stylesheet', 'a'));

        // When
        $bytes = $this->serializer->serialize($document);

        // Then
        static::assertSame("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a xmlns=\"urn:a\"><?xml-stylesheet a?></a>", $bytes);
    }

    /**
     * §9.3 row 22, section 6.5, XML 1.0 §2.6: a processing instruction whose data came to hold the sequence that
     * ends one, which createProcessingInstruction() refuses but appendData() does not.
     */
    #[Test]
    public function itRefusesAProcessingInstructionWhoseDataHoldsTheEndMarker(): void
    {
        // Given
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        $instruction = $xml->createProcessingInstruction('pi', 'a?');
        $root->appendChild($instruction);
        $instruction->appendData('>b');

        // Then
        $this->expectException(SerializationFailed::class);
        $this->expectExceptionMessageIs('A processing instruction holds the sequence that ends one, which XML 1.0 §2.6 forbids (section 6.5).');

        // When
        $this->serializer->serialize($document);
    }

    /**
     * A document built by the factory whose root holds $value in one place.
     */
    private static function documentHolding(string $place, string $value): Document
    {
        $document = new DocumentFactory()->create(new Name('urn:a', 'a'));
        $root = $document->root();
        $xml = $root->ownerDocument;
        static::assertNotNull($xml);
        match ($place) {
            'text' => $root->appendChild($xml->createTextNode($value)),
            'CDATA section' => $root->appendChild($xml->createCDATASection($value)),
            'comment' => $root->appendChild($xml->createComment($value)),
            'processing instruction' => $root->appendChild($xml->createProcessingInstruction('pi', $value)),
            'attribute value' => $root->setAttribute('v', $value),
            default => $root->appendChild($xml->createElementNS('urn:x:' . $value, 'x:e')),
        };

        return $document;
    }
}
