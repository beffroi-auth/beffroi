<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Beffroi\Oidc\Domain\Event\PushedRequestRefused;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 9126, Architecture §4.2
 */
final class PushedAuthorizationTest extends BrowserTestCase
{
    private const string CLIENT = 'oidc-demo';

    private const string SECRET = 'demo-secret-of-at-least-32-characters-long';

    private const string REDIRECT_URI = 'https://demo.test/login/check';

    /**
     * RFC 9126 §2
     */
    #[Test]
    public function theEndpointIsPostOnly(): void
    {
        // When
        $this->browser->request('GET', '/par', self::pushedParameters());

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 9126 §2.2
     */
    #[Test]
    public function aPushedRequestIsAnsweredWithAReferenceThatIsNeverCached(): void
    {
        // When
        $this->push();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
        $answer = self::json($response);
        static::assertStringStartsWith(RequestUri::URN_PREFIX, self::string($answer['request_uri'] ?? null));
        static::assertSame(60, $answer['expires_in'] ?? null);
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function aPushedRequestIsUsedOnceAndSendsTheBrowserOn(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT,
            'request_uri' => $requestUri,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?interaction=', self::string($response->headers->get('Location')));
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function aReferenceIsReadAgainWhileNobodyHasAnsweredTheRequest(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();
        $this->authorize($requestUri);

        // When
        $this->authorize($requestUri);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?interaction=', self::string($response->headers->get('Location')));
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function aReferenceIsRefusedOnceTheRequestItCarriedWasGranted(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();
        $this->authorize($requestUri);
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/login', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);
        static::assertStringStartsWith(self::REDIRECT_URI . '?code=', self::string($this->browser->getResponse()->headers->get('Location')));

        // When
        $this->authorize($requestUri);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('invalid_request_uri', self::string($response->getContent()));
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function aReferencePastItsLifetimeIsRefused(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();
        self::mockTime('+61 seconds');

        // When
        $this->authorize($requestUri);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 9126 §2.2
     */
    #[Test]
    public function aReferencePresentedByAnotherClientIsRefused(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'native-app',
            'request_uri' => $requestUri,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 9126 §2.2, decision 0062
     */
    #[Test]
    public function aReferencePresentedUnderAnIdentifierNobodyRegisteredIsWrittenWithItsReasonAndNoClient(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'a-client-nobody-registered',
            'request_uri' => $requestUri,
        ]);

        // Then
        static::assertSame(
            [[
                'reason' => 'other_client',
                'client' => null,
            ]],
            self::service('doctrine.dbal.default_connection', Connection::class)
                ->fetchAllAssociative(
                    'SELECT reason, client FROM beffroi_journal WHERE act = ?',
                    [PushedRequestRefused::NAME],
                ),
        );
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function theQueryNeverContradictsWhatWasPushed(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri([
            'scope' => 'openid profile',
            'state' => 'state-of-the-client',
        ]);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT,
            'request_uri' => $requestUri,
            'scope' => 'openid email',
            'state' => 'state-of-the-attacker',
        ]);
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/login', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertSame('state-of-the-client', $query['state']);
        static::assertStringStartsWith(self::REDIRECT_URI . '?code=', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * RFC 9126 §6
     */
    #[Test]
    public function aClientThatMustPushIsRefusedAnOrdinaryRequest(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('fapi-app', [
            'redirect_uri' => 'https://fapi.test/callback',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertNull($response->headers->get('Location'));
    }

    /**
     * RFC 9126 §6
     */
    #[Test]
    public function theSameClientIsServedOnceItHasPushedItsRequest(): void
    {
        // Given
        $this->browser->request(
            'POST',
            '/par',
            self::pushedParameters([
                'client_id' => 'fapi-app',
                'redirect_uri' => 'https://fapi.test/callback',
            ]),
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic('fapi-app', 'fapi-secret-of-at-least-32-characters-long'),
            ],
        );
        $requestUri = self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'fapi-app',
            'request_uri' => $requestUri,
        ]);

        // Then
        static::assertStringStartsWith('/login?interaction=', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * RFC 9126 §2.3
     */
    #[Test]
    public function aRefusalAtTheEndpointNeverRedirects(): void
    {
        // When
        $this->push([
            'scope' => 'openid banking',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertNull($response->headers->get('Location'));
        static::assertSame('invalid_scope', self::json($response)['error'] ?? null);
    }

    /**
     * RFC 9126 §2, RFC 6749 §5.2
     */
    #[Test]
    public function aClientThatDoesNotAuthenticateIsRefused(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/par',
            self::pushedParameters(),
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic(self::CLIENT, 'not-the-secret'),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error'] ?? null);
    }

    /**
     * OIDC Discovery §3, RFC 9126 §5
     */
    #[Test]
    public function theMetadataAnnouncesTheEndpoint(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame('https://op.test/par', $metadata['pushed_authorization_request_endpoint'] ?? null);
        static::assertFalse($metadata['require_pushed_authorization_requests'] ?? null);
    }

    /**
     * @param array<string, string|null> $parameters
     */
    private function push(array $parameters = []): void
    {
        $this->browser->request(
            'POST',
            '/par',
            self::pushedParameters($parameters),
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic(self::CLIENT, self::SECRET),
            ],
        );
    }

    /**
     * @param array<string, string|null> $parameters
     */
    private function pushedRequestUri(array $parameters = []): string
    {
        $this->push($parameters);

        return self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);
    }

    private function authorize(string $requestUri): void
    {
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT,
            'request_uri' => $requestUri,
        ]);
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function pushedParameters(array $parameters = []): array
    {
        return self::authorizationParameters(
            self::CLIENT,
            $parameters
            + [
                'redirect_uri' => self::REDIRECT_URI,
            ],
        );
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
