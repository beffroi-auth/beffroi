<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Load;

use App\Load\LoadBudget;
use App\Load\LoadRefusal;
use App\Plane\Plane;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use Beffroi\Core\Domain\Journal\JournalEntry;
use function mb_strlen;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function sprintf;
use function str_replace;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0014, Architecture §5.2
 */
final class OriginLoadBudgetTest extends BrowserTestCase
{
    private const string ADDRESS = '198.51.100.7';

    private const string OTHER_ADDRESS = '198.51.100.8';

    private const int BUDGET = 1;

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_ORIGIN_BUDGET'] = (string) self::BUDGET;
        parent::setUp();
        $this->browser->disableReboot();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_ORIGIN_BUDGET'], $_ENV['BEFFROI_TEST_ORIGIN_BUDGET']);
    }

    #[Test]
    public function everyRouteOfTheTwoPlanesIsRefusedWithTheDelayToWait(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $served = [];
        foreach (self::planeRoutes() as $name => $request) {
            $this->browser->request($request[0], $request[1], server: self::from(self::ADDRESS));
            $response = $this->browser->getResponse();
            if ($response->getStatusCode() !== LoadRefusal::STATUS || (int) $response->headers->get('Retry-After') <= 0) {
                $served[] = sprintf('%s (%s %s): %d', $name, $request[0], $request[1], $response->getStatusCode());
            }
        }

        // Then
        static::assertSame([], $served);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aRouteOfTheHostApplicationIsNotCounted(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/host', server: self::from(self::ADDRESS));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function theBudgetIsCountedByAddress(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/jwks', server: self::from(self::OTHER_ADDRESS));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Decision 0014, RFC 6585 §4, RFC 9126 §2.3, RFC 6749 §11.4
     */
    #[Test]
    public function theRefusalOfTheProtocolPlaneIsADocumentWithoutAnErrorMember(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/jwks', server: self::from(self::ADDRESS));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
        $members = self::json($response);
        static::assertArrayNotHasKey('error', $members);
        static::assertSame(LoadRefusal::DESCRIPTION, $members['error_description']);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function theRefusalOfTheInteractionPlaneIsTheErrorPageOfThePlane(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/login', server: self::from(self::ADDRESS));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        static::assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
        self::assertInteractionHeaders($response);
        static::assertSame(LoadRefusal::PAGE_ERROR, $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'));
    }

    /**
     * Architecture §5.7
     */
    #[Test]
    public function theRefusedPageIsInTheLanguageTheBrowserAsksFor(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request(
            'GET',
            '/login',
            server: self::from(self::ADDRESS)
            + [
                'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
            ],
        );

        // Then
        static::assertSame('fr', $this->browser->getCrawler()->filter('html')->attr('lang'));
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function thePageOfAnAccountIsRefusedBeforeItAsksForASession(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/account/passkeys', server: self::from(self::ADDRESS));

        // Then
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aRefusalReachesTheAuditTrail(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/jwks', server: self::from(self::ADDRESS));

        // Then
        $spent = self::refusals();
        static::assertCount(1, $spent);
        static::assertSame(LoadBudget::ORIGIN, $spent[0]->budget);
        static::assertSame('beffroi_protocol_jwks', $spent[0]->route);
        static::assertNull($spent[0]->client);
        static::assertSame(self::ADDRESS, $spent[0]->context->ipAddress);
    }

    /**
     * Decision 0062
     */
    #[Test]
    public function theActOfARefusalCanNameEveryRouteOfThePlanes(): void
    {
        // When
        $longer = [];
        foreach (self::planeRoutes() as $name => $request) {
            if (mb_strlen($name) > JournalEntry::WORD_LENGTH) {
                $longer[] = $name;
            }
        }

        // Then
        static::assertSame([], $longer);
    }

    private function spendTheBudget(): void
    {
        for ($request = 1; $request <= self::BUDGET; ++$request) {
            $this->browser->request('GET', '/jwks', server: self::from(self::ADDRESS));
            static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    private static function planeRoutes(): iterable
    {
        foreach (self::service('router', RouterInterface::class)->getRouteCollection() as $name => $route) {
            if (Plane::ofRoute($name) === null) {
                continue;
            }
            $methods = $route->getMethods();

            yield self::string($name) => [$methods === [] ? 'GET' : $methods[0], self::pathOf($route)];
        }
    }

    private static function pathOf(Route $route): string
    {
        $path = $route->getPath();
        foreach ($route->compile()->getPathVariables() as $variable) {
            $requirement = $route->getRequirement(self::string($variable)) ?? '[^/]++';
            $value = Uuid::v7()->toRfc4122();
            if (preg_match('#^(?:' . $requirement . ')$#', $value) !== 1) {
                $value = 'name';
            }
            $path = str_replace(sprintf('{%s}', self::string($variable)), $value, $path);
        }

        return $path;
    }

    /**
     * @return array<string, string>
     */
    private static function from(string $address): array
    {
        return [
            'REMOTE_ADDR' => $address,
        ];
    }

    /**
     * @return list<LoadBudgetSpent>
     */
    private static function refusals(): array
    {
        $refusals = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LoadBudgetSpent) {
                $refusals[] = $event;
            }
        }

        return $refusals;
    }
}
