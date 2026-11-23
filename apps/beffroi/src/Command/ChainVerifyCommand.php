<?php

declare(strict_types=1);

namespace App\Command;

use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Exception\BrokenChainException;
use function file_get_contents;
use function is_array;
use function is_string;
use function json_decode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use function trim;

#[AsCommand(
    name: self::NAME,
    description: 'Walk each chain of the tenant whole against its signature, or one chain against a copy of a signed head kept outside the instance, and name the first position that does not follow. Reads and writes nothing.',
)]
final readonly class ChainVerifyCommand
{
    public const string NAME = 'beffroi:chain:verify';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedChain $chains,
        private ChainVerification $verification,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The chain to walk, "journal", "claim_history" or "disclosures"; every one when none is named.')]
        ?string $chain = null,
        #[Option(description: 'A file holding a signed head of that chain, as the log of the channel "chain" printed it: the chain must still hold it.')]
        ?string $against = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        $chains = $this->chains->orTold($io, $chain);
        if ($tenant === null || $chains === []) {
            return Command::FAILURE;
        }
        $copy = null;
        if ($against !== null) {
            $read = @file_get_contents($against);
            if ($chain === null || ! is_string($read)) {
                $io->error($chain === null ? 'A copy is compared with the one chain it signs: name it.' : sprintf('The file "%s" cannot be read.', $against));

                return Command::FAILURE;
            }
            $copy = self::signedHead(trim($read));
        }
        $broken = 0;
        foreach ($chains as $named) {
            try {
                $verified = $copy === null ? $this->verification->whole($tenant, $named) : $this->verification->wholeAgainst($tenant, $named, $copy);
            } catch (BrokenChainException $exception) {
                ++$broken;
                $io->error(sprintf('The chain "%s": %s', $named->name(), $exception->getMessage()));

                continue;
            }
            $io->writeln(
                $verified->end->position === $verified->start->position
                    ? sprintf(' <fg=green>[ok]</> The chain "%s" keeps no row.', $named->name())
                    : sprintf(
                        ' <fg=green>[ok]</> The chain "%s" keeps positions %d to %d, each one following the one before it%s.',
                        $named->name(),
                        $verified->start->position + 1,
                        $verified->end->position,
                        $verified->signed === null
                            ? ', and nothing signed yet'
                            : sprintf(', and its signature holds up to position %d', $verified->signed->head->position),
                    ),
            );
        }

        return $broken === 0 ? Command::SUCCESS : Command::FAILURE;
    }

    /**
     * The compact JWS itself, or the line of the log of the channel "chain" that carries it.
     */
    private static function signedHead(string $read): string
    {
        $line = json_decode($read, true);
        $copy = is_array($line) && is_array($line['context'] ?? null) ? $line['context']['checkpoint'] ?? null : null;

        return is_string($copy) ? $copy : $read;
    }
}
