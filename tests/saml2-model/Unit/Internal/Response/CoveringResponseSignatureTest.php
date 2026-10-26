<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use function array_filter;
use function array_keys;
use Beffroi\Saml2\Model\Internal\Response\CoveringResponseSignature;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\Verified;
use function dirname;
use function file_get_contents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;
use function sprintf;
use function str_contains;
use function str_ends_with;
use function strlen;
use function substr;

/**
 * Section 6.7, enc.md E-15: the proof the model hands Enc before it opens AES-CBC is the document of the verification
 * of the response's signature, and the package builds it nowhere else.
 */
final class CoveringResponseSignatureTest extends TestCase
{
    use ResponseFixtures;

    /**
     * Section 6.7, E-15: the document the proof covers is the one the verification of the response's signature gave.
     */
    #[Test]
    public function itCoversTheDocumentTheVerificationGave(): void
    {
        // Given
        $document = $this->document('encrypted/response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml');
        $verification = SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create())->verification;
        static::assertInstanceOf(Verified::class, $verification);

        // When
        $proof = new CoveringResponseSignature($verification);

        // Then
        static::assertSame($verification->document, $proof->document());
    }

    /**
     * Section 6.7, E-15: one class of the package implements the proof, this one, built from a Verified only.
     */
    #[Test]
    public function thePackageImplementsTheProofInOneClassOnly(): void
    {
        // When
        $implementing = array_keys(array_filter(
            $this->sources(),
            static fn (string $source): bool => str_contains($source, 'CoveringSignatureInterface'),
        ));

        // Then
        static::assertSame(['Internal/Response/CoveringResponseSignature.php'], $implementing);
    }

    /**
     * @return array<string, string> the source of every PHP file of src/, by its path under src/
     */
    private function sources(): array
    {
        $directory = dirname(__DIR__, 5) . '/src/saml2-model/src';
        $sources = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        )) as $file) {
            if (! $file instanceof SplFileInfo || ! str_ends_with($file->getFilename(), '.php')) {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            if ($source === false) {
                throw new RuntimeException(sprintf('%s cannot be read.', $file->getPathname()));
            }
            $sources[substr($file->getPathname(), strlen($directory) + 1)] = $source;
        }

        return $sources;
    }
}
