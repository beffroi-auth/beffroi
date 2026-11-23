<?php

declare(strict_types=1);

namespace App\Doctor;

use App\Scheduler\BeffroiSchedule;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Domain\Chain\ChainInterface;
use Beffroi\Core\Domain\Chain\VerifiedChain;
use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Port\AmbientTenantInterface;
use const DATE_ATOM;
use Psr\Clock\ClockInterface;
use function sprintf;
use Throwable;

/**
 * Decision 0060: the signature of a chain, the row it signs, the first row kept and the rows written since, in a time
 * that does not grow with the chain; red at the first position that does not follow, named and never by what the row
 * holds, and when the schedule stopped signing the chain or walking it whole.
 */
final readonly class ChainHoldsTogether implements CheckInterface
{
    public const string WHAT_IT_MEANS = 'What it means: a row was changed, added or removed in the database after the provider wrote it, or the signature kept beside the keys of the tenant is not the last one the provider wrote. Until it is resolved, the chain is neither signed past it nor cut by its retention.';

    public const string WHAT_TO_DO = 'What makes it green: the database and the key storage restored from the same backup; or, once a person has read the finding, "bin/console beffroi:chain:sign-anew <chain>", which links and signs the chain again as the database holds it and writes that act to the journal.';

    public const string WHAT_TO_DO_WHEN_LATE = 'What makes it green: the worker consuming the schedule, and its log, which says at error why a chain was not signed or cut.';

    /**
     * Twice the longest timed step that walks a chain whole, the retention of the journal and of the history of claims.
     */
    private const string WALKED_WITHIN = '+2 days';

    public function __construct(
        private ChainInterface $chain,
        private AmbientTenantInterface $tenants,
        private ChainVerification $verification,
        private ClockInterface $clock,
    ) {
    }

    public function about(): string
    {
        return sprintf('The chain "%s": each row linked to the one before it, and signed', $this->chain->name());
    }

    public function finding(): Finding
    {
        try {
            $chain = $this->verification->sinceTheSignature($this->tenants->provide(), $this->chain);
        } catch (BrokenChainException $broken) {
            return Finding::red($this->about(), [$broken->getMessage(), self::WHAT_IT_MEANS, self::WHAT_TO_DO]);
        } catch (Throwable $exception) {
            return Finding::red($this->about(), [sprintf('The chain cannot be read: %s', ExceptionTrail::of($exception))]);
        }
        $late = $this->late($chain);
        if ($late !== null) {
            return Finding::red($this->about(), [$late, self::WHAT_TO_DO_WHEN_LATE]);
        }

        return Finding::green($this->about(), self::says($chain));
    }

    private function late(VerifiedChain $chain): ?string
    {
        $now = $this->clock->now();
        $signedWithin = $now->modify(sprintf('-%d seconds', 2 * BeffroiSchedule::CHAIN_SIGNATURE_EVERY));
        if ($chain->signed === null) {
            return $chain->firstMoment !== null && $chain->firstMoment < $signedWithin
                ? sprintf(
                    'Nothing has signed the chain, whose first row is from %s, more than two passes of the schedule ago.',
                    $chain->firstMoment->format(DATE_ATOM),
                )
                : null;
        }
        if ($chain->signed->signedAt < $signedWithin) {
            return sprintf('The chain was last signed at %s, more than two passes of the schedule ago.', $chain->signed->signedAt->format(DATE_ATOM));
        }
        if ($chain->signed->walkedAt->modify(self::WALKED_WITHIN) < $now) {
            return sprintf(
                'The chain was last walked whole at %s, more than two days ago: its retention walks it each day, and "bin/console beffroi:chain:verify %s" walks it now.',
                $chain->signed->walkedAt->format(DATE_ATOM),
                $chain->chain,
            );
        }

        return null;
    }

    private static function says(VerifiedChain $chain): string
    {
        $kept = $chain->end->position - $chain->start->position;
        if ($chain->signed === null) {
            return $kept === 0
                ? 'The chain holds no row yet.'
                : sprintf(
                    'The %d row(s) the chain keeps, positions %d to %d, follow one another; none is signed yet, which the next pass does.',
                    $kept,
                    $chain->start->position + 1,
                    $chain->end->position,
                );
        }

        return sprintf(
            'The chain keeps positions %d to %d; the signature of %s holds up to position %d and the rows written since follow it, %d of them waiting for the next pass; the whole chain was walked up to position %d at %s.',
            $chain->start->position + 1,
            $chain->end->position,
            $chain->signed->signedAt->format(DATE_ATOM),
            $chain->signed->head->position,
            $chain->unsigned(),
            $chain->signed->walked->position,
            $chain->signed->walkedAt->format(DATE_ATOM),
        );
    }
}
