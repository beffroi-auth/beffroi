<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Application\Chain\ChainCheckpoints;
use Beffroi\Core\Application\Chain\ChainCut;
use Beffroi\Core\Application\Chain\ChainRelinking;
use Beffroi\Core\Application\Chain\ChainSignature;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Application\Chain\ChainWalk;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryHeldKeyJwsVerifier;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use function sprintf;
use Symfony\Component\Clock\MockClock;

/**
 * One chain of one tenant, its signatures kept apart, signed under a key of that tenant as the provider signs it.
 */
final readonly class SignedChain
{
    public const int RETENTION = 180;

    public Tenant $tenant;

    public JournalChain $chain;

    public ChainOfWrittenRows $rows;

    public KeptCheckpoints $kept;

    public ChainCheckpoints $checkpoints;

    public MockClock $clock;

    public RecordingEventDispatcher $events;

    private InMemoryTenantKeyRepository $keys;

    private ChainWalk $walk;

    public function __construct()
    {
        $this->tenant = Fixtures::tenant();
        $this->chain = new JournalChain();
        $this->rows = new ChainOfWrittenRows();
        $this->kept = new KeptCheckpoints();
        $this->clock = new MockClock(Fixtures::now());
        $this->events = new RecordingEventDispatcher();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->activate(Keys::pair());
        $this->checkpoints = new ChainCheckpoints(
            $this->kept,
            $this->kept,
            new JwtLibraryJwsSigner(new SealedKeyProvider($this->keys, Keys::opened()), Algorithms::all()),
            new JwtLibraryHeldKeyJwsVerifier($this->keys, Algorithms::all()),
            Algorithms::all(),
        );
        $this->walk = new ChainWalk($this->rows);
    }

    public function signature(): ChainSignature
    {
        return new ChainSignature($this->rows, $this->walk, $this->checkpoints, new WritesAsTheyCome(), $this->clock);
    }

    public function cut(): ChainCut
    {
        return new ChainCut($this->rows, $this->walk, $this->verification(), $this->checkpoints, new WritesAsTheyCome(), $this->clock);
    }

    public function verification(): ChainVerification
    {
        return new ChainVerification($this->rows, $this->walk, $this->checkpoints);
    }

    public function relinking(): ChainRelinking
    {
        return new ChainRelinking($this->rows, $this->rows, $this->checkpoints, new WritesAsTheyCome(), $this->clock, $this->events);
    }

    public function sign(): void
    {
        $this->signature()->sign($this->tenant, $this->chain);
    }

    public function forgetPastTheWindow(): int
    {
        return $this->cut()->forgetPastTheWindow($this->tenant, $this->chain, $this->clock->now()->modify(sprintf('-%d days', self::RETENTION)));
    }

    public static function past(): DateTimeImmutable
    {
        return Fixtures::now()->modify(sprintf('-%d days', self::RETENTION + 1));
    }

    /**
     * The key that signed so far leaves the JWK Set at once, as a rotation for a compromise retires it.
     */
    public function retireTheKeyThatSignedAtOnce(): void
    {
        foreach ($this->keys->findAll($this->tenant) as $key) {
            if ($key->isActive()) {
                $key->startRetiring(Fixtures::now(), Fixtures::now());
                $key->retire(Fixtures::now());
                $this->keys->save($key);
            }
        }
        $this->activate(Keys::otherPair());
    }

    private function activate(GeneratedKeyPair $pair): void
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            Algorithms::rs256(),
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);
    }
}
