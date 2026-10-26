<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use DateInterval;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeySuccession;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Application\Key\NamedKey;
use Beffroi\Core\Application\Key\RetirementWindow;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Core\Port\KeyPairGeneratorInterface;
use Psr\Clock\ClockInterface;

/**
 * The four steps of the life of a key and the window they read, wired over one repository, one clock and
 * one dispatcher: a test of one step puts its key in the state it tests with the steps beside it, and all
 * of them say the same thing about the same tenant.
 */
final readonly class KeyLifecycle
{
    /**
     * The kinds of JWS the tenant issues under test: ten minutes and one hour, so that the longest wins.
     */
    public const string LONGEST_LIFETIME = 'PT1H';

    /**
     * The staging window under test: six minutes, the JWKS max-age of five plus the refetch cooldown.
     */
    public const string STAGING_DELAY = 'PT6M';

    /**
     * The age of a key under test: thirty days, longer than the hour the longest JWS of this tenant lives,
     * which is what the succession requires of an age.
     */
    public const string AGE = 'P30D';

    public InMemoryTenantKeyRepository $keys;

    public RecordingEventDispatcher $events;

    public RetirementWindow $window;

    public KeyStaging $staging;

    public KeyRetirement $retirement;

    public KeyTakeOver $takeOver;

    public KeySuccession $succession;

    /**
     * @param list<KeyBoundArtifactInterface>|null $artifacts the kinds of artifact bound to a key of the tenant; the two above when none is named
     * @param string|null $age how long a key works before a successor is staged for it
     * @param KeyPairGeneratorInterface|null $generator what draws the pairs; the two precomputed ones when none is named
     * @param array<string, RotationSchedule> $families the schedule of the algorithms of that name, a family of their own; the staging delay and the age above for every other
     */
    public function __construct(
        ClockInterface $clock,
        ?array $artifacts = null,
        ?string $age = null,
        ?KeyPairGeneratorInterface $generator = null,
        array $families = [],
    ) {
        $schedules = new FixedRotationSchedules(
            new RotationSchedule(new DateInterval(self::STAGING_DELAY), new DateInterval($age ?? self::AGE)),
            $families,
        );
        $this->keys = new InMemoryTenantKeyRepository();
        $this->events = new RecordingEventDispatcher();
        $this->window = new RetirementWindow(
            $artifacts ?? [
                new FixedLifetimeArtifact(new DateInterval('PT10M')),
                new FixedLifetimeArtifact(new DateInterval(self::LONGEST_LIFETIME)),
            ],
        );
        $named = new NamedKey($this->keys);
        $this->staging = new KeyStaging(
            $this->keys,
            $generator ?? new PrecomputedKeyPairGenerator([Keys::pair(), Keys::otherPair()]),
            Keys::sealer(),
            $schedules,
            $clock,
            $this->events,
        );
        $this->retirement = new KeyRetirement($this->keys, $named, $clock, $this->events);
        $this->takeOver = new KeyTakeOver(
            $this->keys,
            $named,
            $this->staging,
            $this->window,
            $this->retirement,
            $clock,
            $this->events,
        );
        $this->succession = new KeySuccession(
            $this->keys,
            $this->staging,
            $this->window,
            $schedules,
            $clock,
        );
    }
}
