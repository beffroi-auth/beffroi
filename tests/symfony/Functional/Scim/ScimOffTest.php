<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Scim;

use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

/**
 * spec/scim.md section 5.1
 */
final class ScimOffTest extends ScimTestCase
{
    /**
     * Section 5.1
     */
    #[Test]
    public function everyRouteOfTheModuleAnswers404WhileItIsOff(): void
    {
        // When
        $served = [];
        foreach (self::scimRoutes() as $name => [$method, $path]) {
            $this->browser->request($method, $path, server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: '{}');
            $status = $this->browser->getResponse()->getStatusCode();
            if ($status !== Response::HTTP_NOT_FOUND) {
                $served[] = sprintf('%s (%s %s): %d', $name, $method, $path, $status);
            }
        }

        // Then
        static::assertSame([], $served);
    }

    /**
     * Section 5.1
     */
    #[Test]
    public function nothingOfTheModuleIsBuiltWhileItIsOff(): void
    {
        // When
        $built = [
            self::getContainer()->get('test.beffroi.scim.endpoints'),
            self::getContainer()->get('test.beffroi.scim.answers'),
        ];

        // Then
        static::assertSame([null, null], $built);
    }

    /**
     * Section 5.1
     */
    #[Test]
    public function aRouteOfTheModuleWhileItIsOffAnswersNoDocumentOfScim(): void
    {
        // When
        $this->browser->request('POST', '/scim/v2/Users', server: ['CONTENT_TYPE' => self::MEDIA_TYPE], content: '{');

        // Then
        static::assertNotSame(self::MEDIA_TYPE, $this->browser->getResponse()->headers->get('Content-Type'));
    }
}
