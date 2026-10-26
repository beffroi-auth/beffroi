<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\MetadataFetcherInterface;
use function fclose;
use function fopen;
use function is_file;
use function sprintf;
use function str_starts_with;
use function stream_get_contents;
use function strlen;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * The bytes of the metadata of a peer at the location its declaration names, a service provider or an upstream
 * identity provider (beffroi/saml, spec/saml.md section 6.2 step 2, section 6.10 step 2). An https URL is read with one GET, nothing sent but the request and the media type of SAML
 * metadata, no redirect followed (decision 0006): the declaration names where the metadata are, and nobody moves
 * them. Anything else is a file of the deployment, and nothing a stream wrapper would go and fetch, the declaration
 * having refused every other location already. Either way the read stops as soon as it is longer than any metadata
 * the loader accepts, and an URL that hangs is given up after the timeout, a worker of the schedule or a terminal
 * waiting on it.
 */
final readonly class MetadataFetcher implements MetadataFetcherInterface
{
    /**
     * Seconds an https location has to answer whole (spec/saml.md section 7).
     */
    public const float TIMEOUT = 10.0;

    public function __construct(
        private HttpClientInterface $http,
        private float $timeout = self::TIMEOUT,
    ) {
    }

    public function fetch(MetadataLocation $location): string
    {
        return str_starts_with($location->value, 'https://') ? $this->download($location->value) : $this->read($location->value);
    }

    /**
     * @throws MetadataRefusedException
     */
    private function read(string $path): string
    {
        $file = is_file($path) ? @fopen($path, 'rb') : false;
        if ($file === false) {
            throw new MetadataRefusedException(sprintf('The file %s cannot be read.', $path));
        }
        $bytes = stream_get_contents($file, self::MAX_BYTES + 1);
        fclose($file);
        if ($bytes === false) {
            throw new MetadataRefusedException(sprintf('The file %s cannot be read.', $path));
        }

        return self::bounded($bytes, $path);
    }

    /**
     * @throws MetadataRefusedException
     */
    private function download(string $url): string
    {
        try {
            $response = $this->http->request('GET', $url, [
                'headers' => [
                    'Accept' => 'application/samlmetadata+xml',
                ],
                'max_redirects' => 0,
                'timeout' => $this->timeout,
                'max_duration' => $this->timeout,
            ]);
            $status = $response->getStatusCode();
            if ($status >= 300 && $status < 400) {
                throw new MetadataRefusedException(sprintf(
                    '%s redirects, and no outbound request follows a redirect; declare the URL the metadata are published at.',
                    $url,
                ));
            }
            if ($status < 200 || $status >= 300) {
                throw new MetadataRefusedException(sprintf('%s answered %d.', $url, $status));
            }
            $body = '';
            foreach ($this->http->stream($response) as $chunk) {
                $body = self::bounded($body . $chunk->getContent(), $url);
            }

            return $body;
        } catch (MetadataRefusedException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new MetadataRefusedException(sprintf('%s cannot be reached: %s', $url, ExceptionTrail::of($exception)), 0, $exception);
        }
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function bounded(string $bytes, string $location): string
    {
        if (strlen($bytes) > self::MAX_BYTES) {
            throw new MetadataRefusedException(sprintf(
                '%s holds more than %d bytes, which no metadata the loader accepts holds (spec/saml.md section 7).',
                $location,
                self::MAX_BYTES,
            ));
        }

        return $bytes;
    }
}
