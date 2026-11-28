<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Scim;

use Beffroi\Scim\Domain\Error\NotServed;
use Beffroi\Scim\Domain\Error\ProviderFailure;
use Beffroi\Scim\Domain\Name\Schemas;
use Beffroi\Scim\Domain\Request\BodyLength;
use Beffroi\Scim\Domain\Request\JsonDocument;
use Beffroi\Scim\Domain\Request\JsonStructure;
use Beffroi\Scim\Domain\Request\MediaType;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_repeat;
use Symfony\Component\HttpFoundation\Response;

/**
 * spec/scim.md section 5.1, section 6.1 steps 4 and 5, P-5, P-19, P-21
 */
final class ScimEndpointsTest extends ScimTestCase
{
    private const string USERS = '/scim/v2/Users';

    protected function setUp(): void
    {
        $_SERVER[self::SWITCH] = 'true';
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_PLANE'], $_ENV['BEFFROI_PLANE']);
    }

    /**
     * Section 5.1, RFC 7644 §8.1, RFC 9111 §5.2.2.5
     */
    #[Test]
    public function everyAnswerOfTheModuleIsADocumentOfScimThatNoCacheKeeps(): void
    {
        // Given
        $requests = [
            ...self::scimRoutes(),
            'a path that names no endpoint' => ['GET', '/scim/v2/Unknown'],
            'a method an endpoint does not serve' => ['DELETE', self::USERS],
            'a failure' => ['GET', '/scim/v2/Failing'],
            'the base path' => ['GET', '/scim/v2'],
            'a path ending with a slash' => ['GET', self::USERS . '/'],
        ];

        // When
        $answered = [];
        foreach ($requests as $name => [$method, $path]) {
            $this->browser->request($method, $path, server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: '{}');
            $response = $this->browser->getResponse();
            if ($response->headers->get('Content-Type') !== self::MEDIA_TYPE || ! $response->headers->hasCacheControlDirective('no-store')) {
                $answered[] = sprintf('%s (%s %s): %s', $name, $method, $path, (string) $response->headers->get('Content-Type'));
            }
        }

        // Then
        static::assertSame([], $answered);
    }

    /**
     * Section 8, RFC 7644 §3.12
     */
    #[Test]
    #[DataProvider('provideOperationsNotServed')]
    public function anOperationTheProviderDoesNotServeAnswers501(string $method, string $path): void
    {
        // When
        $this->browser->request($method, $path, server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: '{}');

        // Then
        static::assertSame(NotServed::DETAIL, self::scimError($this->browser->getResponse(), 501)['detail'] ?? null);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideOperationsNotServed(): iterable
    {
        yield 'a read' => ['GET', self::USERS];
        yield 'a write, once its body is read' => ['POST', self::USERS];
        yield 'the configuration of the service provider' => ['GET', '/scim/v2/ServiceProviderConfig'];
        yield 'a bulk request' => ['POST', '/scim/v2/Bulk'];
        yield 'a search by POST' => ['POST', '/scim/v2/Users/.search'];
        yield 'the alias of the authenticated subject' => ['GET', '/scim/v2/Me'];
    }

    /**
     * P-5, section 7, RFC 9110 §15.5.14
     */
    #[Test]
    public function aBodyPastTheBoundIsRefusedBeforeItIsRead(): void
    {
        // When
        $this->browser->request('POST', self::USERS, server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: str_repeat('{', BodyLength::BYTES + 1));

        // Then
        static::assertSame(BodyLength::DETAIL, self::scimError($this->browser->getResponse(), 413)['detail'] ?? null);
    }

    /**
     * Section 6.1 step 4, RFC 7644 §3.12
     */
    #[Test]
    public function aBodyThatIsNotJsonAnswersInvalidSyntax(): void
    {
        // When
        $this->browser->request(
            'PUT',
            self::USERS . '/2819c223-7f76-453a-919d-413861904646',
            server: ['CONTENT_TYPE' => self::MEDIA_TYPE],
            content: 'userName=bjensen',
        );

        // Then
        $error = self::scimError($this->browser->getResponse(), 400);
        static::assertSame(['invalidSyntax', JsonStructure::NOT_JSON], [$error['scimType'] ?? null, $error['detail'] ?? null]);
    }

    /**
     * Section 6.1 step 4
     */
    #[Test]
    public function aBodyThatIsNoObjectAnswersInvalidSyntax(): void
    {
        // When
        $this->browser->request('POST', '/scim/v2/Groups', server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: '[]');

        // Then
        $error = self::scimError($this->browser->getResponse(), 400);
        static::assertSame(['invalidSyntax', JsonDocument::NOT_AN_OBJECT], [$error['scimType'] ?? null, $error['detail'] ?? null]);
    }

    /**
     * P-5, RFC 7493 §2.3, RFC 7644 §3.5.2
     */
    #[Test]
    public function aNameHeldTwiceUnderAnEscapeAnswersInvalidSyntax(): void
    {
        // When
        $this->browser->request(
            'PATCH',
            self::USERS . '/2819c223-7f76-453a-919d-413861904646',
            server: ['CONTENT_TYPE' => self::MEDIA_TYPE],
            content: '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","\\u006fp":"remove","path":"members"}]}',
        );

        // Then
        $error = self::scimError($this->browser->getResponse(), 400);
        static::assertSame(['invalidSyntax', JsonStructure::NAME_TWICE], [$error['scimType'] ?? null, $error['detail'] ?? null]);
    }

    /**
     * Section 6.1 step 4, RFC 7644 §3.8, RFC 9110 §8.3.2
     */
    #[Test]
    #[DataProvider('provideReadTypes')]
    public function aBodyOfAJsonTypeInUtf8IsRead(string $contentType): void
    {
        // When
        $this->browser->request('POST', self::USERS, server: ['CONTENT_TYPE' => $contentType], content: '{"userName":"bjensen"}');

        // Then
        static::assertSame(NotServed::DETAIL, self::scimError($this->browser->getResponse(), 501)['detail'] ?? null);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideReadTypes(): iterable
    {
        yield 'no type' => [''];
        yield 'a charset in capitals' => ['application/scim+json; charset=UTF-8'];
        yield 'the type of JSON' => ['application/json'];
    }

    /**
     * Section 6.1 step 4, RFC 9110 §15.5.16
     */
    #[Test]
    public function aBodyOfAnotherTypeAnswers415(): void
    {
        // When
        $this->browser->request('POST', self::USERS, server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: '{"userName":"bjensen"}');

        // Then
        static::assertSame(MediaType::DETAIL, self::scimError($this->browser->getResponse(), 415)['detail'] ?? null);
    }

    /**
     * P-21, RFC 7643 §2.1
     */
    #[Test]
    public function aNameThatUnicodeWouldFoldOntoAnotherAnswersInvalidSyntax(): void
    {
        // When
        $this->browser->request(
            'POST',
            self::USERS,
            server: ['CONTENT_TYPE' => self::MEDIA_TYPE],
            content: '{"userName":"bjensen","pa\\u017f\\u017fword":"t1meMa$heen"}',
        );

        // Then
        $error = self::scimError($this->browser->getResponse(), 400);
        static::assertSame(['invalidSyntax', Schemas::NOT_A_NAME], [$error['scimType'] ?? null, $error['detail'] ?? null]);
    }

    /**
     * P-21, RFC 7643 §2.3.7, §4.2
     */
    #[Test]
    public function theReferenceOfAMemberIsReadAsAName(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/scim/v2/Groups',
            server: ['CONTENT_TYPE' => self::MEDIA_TYPE],
            content: '{"displayName":"Tour Guides","members":[{"value":"2819c223-7f76-453a-919d-413861904646","$ref":"https://op.test/scim/v2/Users/2819c223-7f76-453a-919d-413861904646"}]}',
        );

        // Then
        static::assertSame(NotServed::DETAIL, self::scimError($this->browser->getResponse(), 501)['detail'] ?? null);
    }

    /**
     * Section 6.12, RFC 7644 §3.12 Table 8
     */
    #[Test]
    #[DataProvider('providePathsThatNameNoEndpoint')]
    public function aPathThatNamesNoEndpointAnswers404WithoutThePath(string $path): void
    {
        // When
        $this->browser->request('GET', $path);

        // Then
        static::assertSame('Not Found', self::scimError($this->browser->getResponse(), 404)['detail'] ?? null);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePathsThatNameNoEndpoint(): iterable
    {
        yield 'an endpoint RFC 7644 does not define' => ['/scim/v2/Unknown'];
        yield 'the base path' => ['/scim/v2'];
        yield 'an endpoint followed by a slash, which is not sent to the endpoint' => [self::USERS . '/'];
    }

    /**
     * Section 6.12, RFC 9110 §15.5.6
     */
    #[Test]
    public function aMethodAnEndpointDoesNotServeAnswers405WithTheMethodsItServes(): void
    {
        // When
        $this->browser->request('DELETE', self::USERS);

        // Then
        $response = $this->browser->getResponse();
        self::scimError($response, 405);
        static::assertSame('GET, POST', $response->headers->get('Allow'));
    }

    /**
     * P-19, section 6.12
     */
    #[Test]
    public function aFailureNoRuleNamesAnswers500WithADetailThatCarriesNothing(): void
    {
        // When
        $this->browser->request('GET', '/scim/v2/Failing');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(ProviderFailure::DETAIL, self::scimError($response, 500)['detail'] ?? null);
        static::assertStringNotContainsString(FailingController::MESSAGE, (string) $response->getContent());
    }

    /**
     * Architecture §5.2, the planes
     */
    #[Test]
    public function aProcessOfTheInteractionPlaneAnswersAPathOfTheModuleAsAnUnknownPath(): void
    {
        // Given
        $_SERVER['BEFFROI_PLANE'] = 'interaction';
        $browser = self::browser(null, self::kernelOptions());

        // When
        $browser->request('GET', self::USERS);

        // Then
        $response = $browser->getResponse();
        static::assertSame([Response::HTTP_NOT_FOUND, false], [$response->getStatusCode(), $response->headers->get('Content-Type') === self::MEDIA_TYPE]);
    }
}
