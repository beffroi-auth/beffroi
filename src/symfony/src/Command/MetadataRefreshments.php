<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Saml\Application\Metadata\MetadataRefreshment;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * What the refresh of the metadata of SAML peers came to, told to a terminal (beffroi/saml, spec/saml.md sections 6.2
 * and 6.10): each outcome on a line of its own, a refusal as an error, and the command failing when one was refused,
 * whatever the role of the peers.
 */
final readonly class MetadataRefreshments
{
    /**
     * @param list<MetadataRefreshment> $refreshments
     *
     * @return int the exit code of the command
     */
    public static function told(SymfonyStyle $io, array $refreshments): int
    {
        $refused = 0;
        foreach ($refreshments as $refreshment) {
            if ($refreshment->refused) {
                ++$refused;
                $io->error($refreshment->what);
                continue;
            }
            $io->success($refreshment->what);
        }

        return $refused === 0 ? Command::SUCCESS : Command::FAILURE;
    }
}
