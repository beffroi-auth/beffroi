<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Event;

use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class LoadBudgetSpentTest extends TestCase
{
    /**
     * Decision 0014, decision 0062
     */
    #[Test]
    public function itSaysWhichBudgetItSpentAndTheRouteItRefused(): void
    {
        // When
        $event = new LoadBudgetSpent(Fixtures::now(), Fixtures::tenant(), Fixtures::context(), 'client', 'beffroi_protocol_token', 'oidc-demo');

        // Then
        static::assertSame(['client', 'beffroi_protocol_token'], [$event->refusalReason(), $event->refusedMethod()]);
    }

    /**
     * Decision 0062
     */
    #[Test]
    public function aRequestRoutedNowhereRefusedNoMethod(): void
    {
        // Given
        $event = new LoadBudgetSpent(Fixtures::now(), Fixtures::tenant(), Fixtures::context(), 'origin', '', null);

        // When / Then
        static::assertNull($event->refusedMethod());
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function itNamesTheClientThatSpentTheBudget(): void
    {
        // When
        $event = new LoadBudgetSpent(Fixtures::now(), Fixtures::tenant(), Fixtures::context(), 'client', 'beffroi_protocol_token', 'oidc-demo');

        // Then
        static::assertSame('oidc-demo', $event->clientId);
    }
}
