<?php

declare(strict_types=1);

namespace App\Command;

use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Chain\ChainRelinking;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Exception\BrokenChainException;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Link and sign one chain of the tenant again as the database holds it, once a person has read what its check found. Says what the check finds first, asks for the slug to be typed back, and writes the act to the journal.',
)]
final readonly class ChainSignAnewCommand
{
    public const string NAME = 'beffroi:chain:sign-anew';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedChain $chains,
        private ChainVerification $verification,
        private ChainRelinking $relinking,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The chain to sign anew, "journal", "claim_history" or "disclosures".')]
        string $chain,
        #[Argument(description: 'The slug of the tenant, typed back: what the chain held before is no longer told apart from what it holds now.')]
        ?string $slug = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        $named = $this->chains->orTold($io, $chain)[0] ?? null;
        if ($tenant === null || $named === null) {
            return Command::FAILURE;
        }
        try {
            $finding = sprintf(
                'The check of the chain "%s" finds it whole, up to position %d.',
                $named->name(),
                $this->verification->whole($tenant, $named)->end->position,
            );
        } catch (BrokenChainException $broken) {
            $finding = sprintf('The check of the chain "%s" finds: %s', $named->name(), $broken->getMessage());
        }
        if ($slug !== $tenant->slug) {
            $io->error([
                $finding,
                $slug === null
                    ? sprintf('Type the slug of the tenant back to sign the chain anew: "%s %s %s".', self::NAME, $named->name(), $tenant->slug)
                    : sprintf('"%s" is not the slug of the tenant this deployment is configured for, which is "%s".', $slug, $tenant->slug),
                'Signing anew links every row the database holds of this chain again, and signs it: whatever was changed, added or removed before is no longer told apart from the rest.',
            ]);

            return Command::INVALID;
        }
        try {
            $relinked = $this->relinking->signAnew($tenant, $named, $this->contexts->fromConsole(self::NAME));
        } catch (KeyNotFoundException|KmsUnavailableException|RuntimeException $failure) {
            $io->error(sprintf('The chain "%s" was not signed anew: %s', $named->name(), ExceptionTrail::of($failure)));

            return Command::FAILURE;
        }
        $io->success([
            $finding,
            sprintf(
                'The chain "%s" is linked and signed anew from position %d to position %d, and the journal holds the act.',
                $named->name(),
                $relinked->start->position + 1,
                $relinked->head->position,
            ),
        ]);

        return Command::SUCCESS;
    }
}
