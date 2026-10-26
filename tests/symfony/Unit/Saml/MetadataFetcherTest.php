<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\MetadataFetcher;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\MetadataFetcherInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use function file_put_contents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * beffroi/saml, spec/saml.md section 6.2 step 2 and section 7: the metadata of a service provider read from a file of
 * the deployment or from an https URL, one GET, no redirect followed (decision 0006), bounded by the maxBytes of Core.
 */
final class MetadataFetcherTest extends TestCase
{
    private const string URL = 'https://sp.example.com/saml/metadata';

    private ?string $file = null;

    protected function tearDown(): void
    {
        if ($this->file !== null) {
            unlink($this->file);
        }
    }

    #[Test]
    public function itReadsAFileOfTheDeployment(): void
    {
        // When
        $bytes = new MetadataFetcher(new MockHttpClient())->fetch(new MetadataLocation(ServiceProviderDocuments::path()));

        // Then
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $bytes);
    }

    #[Test]
    public function itRefusesAFileThatIsNotThere(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The file /nowhere/sp-metadata.xml cannot be read.');

        // When
        new MetadataFetcher(new MockHttpClient())->fetch(new MetadataLocation('/nowhere/sp-metadata.xml'));
    }

    #[Test]
    public function itRefusesADirectory(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The file /tmp cannot be read.');

        // When
        new MetadataFetcher(new MockHttpClient())->fetch(new MetadataLocation('/tmp'));
    }

    /**
     * Section 7: a file larger than any metadata the loader accepts is refused rather than handed to it.
     */
    #[Test]
    public function itRefusesAFileLargerThanAnyMetadata(): void
    {
        // Given
        $this->file = self::temporaryFile(str_repeat('a', MetadataFetcherInterface::MAX_BYTES + 1));

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIsOrContains('holds more than 1048576 bytes, which no metadata the loader accepts holds (spec/saml.md section 7).');

        // When
        new MetadataFetcher(new MockHttpClient())->fetch(new MetadataLocation($this->file));
    }

    #[Test]
    public function aFileOfTheBoundIsRead(): void
    {
        // Given
        $this->file = self::temporaryFile(str_repeat('a', MetadataFetcherInterface::MAX_BYTES));

        // When
        $bytes = new MetadataFetcher(new MockHttpClient())->fetch(new MetadataLocation($this->file));

        // Then
        static::assertSame(MetadataFetcherInterface::MAX_BYTES, \strlen($bytes));
    }

    /**
     * One GET, asking for the media type of SAML metadata, nothing followed.
     */
    #[Test]
    public function itReadsAnHttpsUrl(): void
    {
        // Given
        $response = new MockResponse(ServiceProviderDocuments::simpleSamlPhp());
        $fetcher = new MetadataFetcher(new MockHttpClient($response));

        // When
        $bytes = $fetcher->fetch(new MetadataLocation(self::URL));

        // Then
        static::assertSame(ServiceProviderDocuments::simpleSamlPhp(), $bytes);
        static::assertSame('GET', $response->getRequestMethod());
        $headers = $response->getRequestOptions()['headers'];
        static::assertIsArray($headers);
        static::assertContains('Accept: application/samlmetadata+xml', $headers);
        static::assertSame(0, $response->getRequestOptions()['max_redirects']);
        static::assertSame(MetadataFetcher::TIMEOUT, $response->getRequestOptions()['timeout']);
        static::assertSame(MetadataFetcher::TIMEOUT, $response->getRequestOptions()['max_duration']);
    }

    /**
     * Decision 0006: no outbound request follows a redirect, the declaration naming where the metadata are.
     */
    #[Test]
    public function itRefusesToFollowARedirect(): void
    {
        // Given
        $fetcher = new MetadataFetcher(new MockHttpClient(new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => 'https://elsewhere.example/metadata',
            ],
        ])));

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('https://sp.example.com/saml/metadata redirects, and no outbound request follows a redirect; declare the URL the metadata are published at.');

        // When
        $fetcher->fetch(new MetadataLocation(self::URL));
    }

    #[Test]
    public function itRefusesAnAnswerOtherThanASuccess(): void
    {
        // Given
        $fetcher = new MetadataFetcher(new MockHttpClient(new MockResponse('', [
            'http_code' => 404,
        ])));

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('https://sp.example.com/saml/metadata answered 404.');

        // When
        $fetcher->fetch(new MetadataLocation(self::URL));
    }

    #[Test]
    public function itRefusesAnInformationalAnswer(): void
    {
        // Given
        $fetcher = new MetadataFetcher(new MockHttpClient(new MockResponse('', [
            'http_code' => 199,
        ])));

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIsOrContains('https://sp.example.com/saml/metadata');

        // When
        $fetcher->fetch(new MetadataLocation(self::URL));
    }

    /**
     * Section 7: the read stops as soon as the body is longer than any metadata the loader accepts.
     */
    #[Test]
    public function itRefusesAnAnswerLargerThanAnyMetadata(): void
    {
        // Given
        $fetcher = new MetadataFetcher(new MockHttpClient(new MockResponse([str_repeat('a', MetadataFetcherInterface::MAX_BYTES), 'a'])));

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('https://sp.example.com/saml/metadata holds more than 1048576 bytes, which no metadata the loader accepts holds (spec/saml.md section 7).');

        // When
        $fetcher->fetch(new MetadataLocation(self::URL));
    }

    #[Test]
    public function itRefusesAUrlThatCannotBeReached(): void
    {
        // Given
        $fetcher = new MetadataFetcher(new MockHttpClient(static fn (): MockResponse => throw new TransportException('Could not resolve host.')));

        // When
        try {
            $fetcher->fetch(new MetadataLocation(self::URL));
            static::fail('A URL that cannot be reached is read.');
        } catch (MetadataRefusedException $exception) {
            // Then
            static::assertStringStartsWith('https://sp.example.com/saml/metadata cannot be reached: ', $exception->getMessage());
            static::assertInstanceOf(TransportException::class, $exception->getPrevious());
        }
    }

    private static function temporaryFile(string $bytes): string
    {
        $file = tempnam(sys_get_temp_dir(), 'metadata');
        if ($file === false) {
            static::fail('No temporary file.');
        }
        file_put_contents($file, $bytes);

        return $file;
    }
}
