<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Update\AssetDownload;
use Beffroi\Tui\Update\ReleaseAsset;
use Beffroi\Tui\Update\SelfUpdateException;
use function array_column;
use function file_get_contents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;
use Symfony\Component\HttpClient\Response\MockResponse;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * A file of a release downloaded to disk, one redirection away at most.
 */
final class AssetDownloadTest extends TestCase
{
    private const string URL = 'https://github.com/beffroi-auth/beffroi/releases/download/0.0.2/beffroi-tui.phar';

    private const string STORED = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/beffroi-tui.phar';

    private string $path;

    protected function setUp(): void
    {
        $this->path = sprintf('%s/beffroi-tui-download-%s', sys_get_temp_dir(), uniqid());
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    #[Test]
    public function theFileIsDownloadedFromWhereTheOneRedirectionSendsIt(): void
    {
        // Given
        $http = RecordedRequests::answering([self::redirectedTo(self::STORED), new MockResponse('the new program')]);

        // When
        new AssetDownload($http->client)->to(new ReleaseAsset('beffroi-tui.phar', self::URL, 15), $this->path);

        // Then
        static::assertSame(
            [[self::URL, self::STORED], 'the new program'],
            [array_column($http->requests, 'url'), file_get_contents($this->path)],
        );
    }

    #[Test]
    public function aFileServedWithoutARedirectionIsDownloaded(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('the new program')]);

        // When
        new AssetDownload($http->client)->to(new ReleaseAsset('beffroi-tui.phar', self::URL, 15), $this->path);

        // Then
        static::assertSame('the new program', file_get_contents($this->path));
    }

    #[Test]
    #[DataProvider('provideLocationsElsewhere')]
    public function aRedirectionElsewhereThanTheStorageOfTheReleaseFilesIsNotFollowed(string $location): void
    {
        // Given
        $http = RecordedRequests::answering([self::redirectedTo($location)]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The download of beffroi-tui.phar is redirected to "%s", which is not under https://release-assets.githubusercontent.com/.',
            $location,
        ));

        // When
        new AssetDownload($http->client)->to(new ReleaseAsset('beffroi-tui.phar', self::URL, 15), $this->path);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLocationsElsewhere(): iterable
    {
        yield 'plain HTTP' => ['http://release-assets.githubusercontent.com/beffroi-tui.phar'];
        yield 'a relative address' => ['/beffroi-tui.phar'];
        yield 'another host' => ['https://elsewhere.example/beffroi-tui.phar'];
        yield 'a host that begins like it' => ['https://release-assets.githubusercontent.com.elsewhere.example/beffroi-tui.phar'];
        yield 'no address' => [''];
    }

    #[Test]
    public function aSecondRedirectionIsNotFollowed(): void
    {
        // Given
        $http = RecordedRequests::answering([self::redirectedTo(self::STORED), self::redirectedTo('https://elsewhere.example/beffroi-tui.phar')]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('The download of beffroi-tui.phar was answered 302.');

        // When
        new AssetDownload($http->client)->to(new ReleaseAsset('beffroi-tui.phar', self::URL, 15), $this->path);
    }

    #[Test]
    public function aFileLargerThanTheReleaseAnnouncesIsCut(): void
    {
        // Given
        $http = RecordedRequests::answering([self::redirectedTo(self::STORED), new MockResponse(str_repeat('a', 16))]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('The file beffroi-tui.phar cannot be downloaded: The answer is larger than the 15 octets this program reads of one.');

        // When
        new AssetDownload($http->client)->to(new ReleaseAsset('beffroi-tui.phar', self::URL, 15), $this->path);
    }

    #[Test]
    public function aFileThatIsNotServedIsRefused(): void
    {
        // Given
        $http = RecordedRequests::answering([self::redirectedTo(self::STORED), new MockResponse('', ['http_code' => 404])]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('The download of beffroi-tui.phar was answered 404.');

        // When
        new AssetDownload($http->client)->to(new ReleaseAsset('beffroi-tui.phar', self::URL, 15), $this->path);
    }

    private static function redirectedTo(string $location): MockResponse
    {
        return new MockResponse('', ['http_code' => 302, 'response_headers' => ['Location' => $location]]);
    }
}
