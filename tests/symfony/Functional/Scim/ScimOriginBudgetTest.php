<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Scim;

use App\Load\LoadRefusal;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * spec/scim.md section 6.1 step 0, decision 0014
 */
final class ScimOriginBudgetTest extends ScimTestCase
{
    private const string BUDGET = 'BEFFROI_TEST_ORIGIN_BUDGET';

    protected function setUp(): void
    {
        $_SERVER[self::SWITCH] = 'true';
        $_SERVER[self::BUDGET] = '1';
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER[self::BUDGET], $_ENV[self::BUDGET]);
    }

    /**
     * Section 6.1 step 0, decision 0014, RFC 6585 §4, RFC 7644 §3.12
     */
    #[Test]
    public function theBudgetOfTheOriginIsSpentBeforeTheBodyIsReadAndRefusedWithTheErrorDocument(): void
    {
        // Given
        $this->browser->request('GET', '/scim/v2/Users');
        static::assertSame(Response::HTTP_NOT_IMPLEMENTED, $this->browser->getResponse()->getStatusCode());

        // When
        $this->browser->request('POST', '/scim/v2/Users', server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: '{');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(LoadRefusal::DESCRIPTION, self::scimError($response, 429)['detail'] ?? null);
        static::assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
    }
}
