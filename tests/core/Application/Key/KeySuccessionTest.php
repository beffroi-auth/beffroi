<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use function array_map;
use DateInterval;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeySuccession;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FixedLifetimeArtifact;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeyLifecycle;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #455: an active key that has worked for the age of a key gets a successor, staged and not
 * activated, so that a relying party sees the new "kid" before anything is signed with it.
 */
final class KeySuccessionTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $repository;

    private MockClock $clock;

    private RequestContext $context;

    private KeyStaging $staging;

    private KeyTakeOver $takeOver;

    private KeySuccession $succession;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock('2026-09-15T14:00:00+00:00');
        $this->context = RequestContext::unknown($this->clock->now());
        $lifecycle = new KeyLifecycle($this->clock);
        $this->repository = $lifecycle->keys;
        $this->staging = $lifecycle->staging;
        $this->takeOver = $lifecycle->takeOver;
        $this->succession = $lifecycle->succession;
    }

    #[Test]
    public function aKeyThatHasWorkedForItsAgeGetsASuccessorStaged(): void
    {
        // Given
        $first = $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+30 days');

        // When
        $staged = $this->succession->stageSuccessorsDue($this->tenant, $this->context);

        // Then
        static::assertCount(1, $staged);
        static::assertTrue($staged[0]->isStaged());
        static::assertSame(Algorithms::rs256()->name(), $staged[0]->algorithm->name());
        static::assertEquals($this->clock->now()->add(new DateInterval(KeyLifecycle::STAGING_DELAY)), $staged[0]->activationDueAt);
        static::assertSame($first, $this->repository->findActive($this->tenant, Algorithms::rs256()));
    }

    /**
     * Issue #738: a key is old by the age of its family, so that a family that works a year gets no successor
     * when the keys of the others, active as long, get theirs.
     */
    #[Test]
    public function aKeyIsOldByTheAgeOfItsFamily(): void
    {
        // Given
        $lifecycle = new KeyLifecycle($this->clock, generator: new JwtLibraryKeyPairGenerator(Algorithms::everyUse()), families: [
            Algorithms::es256()->name() => new RotationSchedule(new DateInterval('P7D'), new DateInterval('P365D')),
        ]);
        $lifecycle->takeOver->rotate($this->tenant, Algorithms::edDsa(), $this->context);
        $lifecycle->takeOver->rotate($this->tenant, Algorithms::es256(), $this->context);
        $this->clock->modify('+30 days');

        // When
        $staged = $lifecycle->succession->stageSuccessorsDue($this->tenant, $this->context);

        // Then
        static::assertSame([Algorithms::edDsa()->name()], array_map(static fn (TenantKey $key): string => $key->algorithm->name(), $staged));
    }

    #[Test]
    public function aKeyInsideItsAgeGetsNothing(): void
    {
        // Given
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+29 days');

        // When
        $staged = $this->succession->stageSuccessorsDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $staged);
    }

    /**
     * The tick that follows finds the successor of the previous one and stages nothing: what makes it
     * idempotent is the key it looks at, not a flag it keeps.
     */
    #[Test]
    public function theTickThatFollowsStagesNothing(): void
    {
        // Given
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+30 days');
        $this->succession->stageSuccessorsDue($this->tenant, $this->context);

        // When
        $again = $this->succession->stageSuccessorsDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $again);
    }

    /**
     * The age is counted from the activation and not from the creation: a key that waited its staging
     * window has not worked for that window.
     */
    #[Test]
    public function theAgeIsCountedFromTheActivationAndNotFromTheCreation(): void
    {
        // Given
        $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+6 minutes');
        $this->takeOver->activateDue($this->tenant, $this->context);
        $this->clock->modify('+30 days');
        $this->clock->modify('-7 minutes');

        // When
        $staged = $this->succession->stageSuccessorsDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $staged);
    }

    /**
     * A staged key that is not due for activation yet is still a successor: the step looks at what the
     * JWK Set publishes and not at what it would activate.
     */
    #[Test]
    public function anAlgorithmWhoseSuccessorIsStagedByHandGetsNothing(): void
    {
        // Given
        $this->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+30 days');
        $this->staging->stage($this->tenant, Algorithms::rs256(), $this->context);

        // When
        $staged = $this->succession->stageSuccessorsDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $staged);
    }

    /**
     * An age that does not outlast the window a retiring key holds the JWK Set open for would leave a key
     * behind at every rotation, so the step refuses rather than growing the set (decision 0006). As long
     * as the window is not longer than it: the successor would start retiring the key it took over from
     * at the very instant that key left, and one tick of the planning late is one key too many.
     */
    #[Test]
    #[DataProvider('provideAgesThatDoNotOutlastTheWindow')]
    public function anAgeThatDoesNotOutlastTheRetirementWindowIsRefused(string $age): void
    {
        // Given
        $lifecycle = new KeyLifecycle($this->clock, [new FixedLifetimeArtifact(new DateInterval(KeyLifecycle::LONGEST_LIFETIME))], $age);
        $lifecycle->takeOver->rotate($this->tenant, Algorithms::rs256(), $this->context);
        $this->clock->modify('+1 hour');

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('the age of a key is longer than that window');

        // When
        $lifecycle->succession->stageSuccessorsDue($this->tenant, $this->context);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAgesThatDoNotOutlastTheWindow(): iterable
    {
        yield 'shorter than the window' => ['PT30M'];
        yield 'as long as the window' => [KeyLifecycle::LONGEST_LIFETIME];
    }
}
