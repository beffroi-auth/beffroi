<?php

declare(strict_types=1);

namespace App\Doctrine\Chain;

use Beffroi\Oidc\Domain\Disclosure\DisclosureChain;

final readonly class DisclosureTable implements ChainedTableInterface
{
    public function chain(): string
    {
        return DisclosureChain::NAME;
    }

    public function table(): string
    {
        return 'beffroi_disclosure';
    }

    public function momentColumn(): string
    {
        return 'handed_over_at';
    }

    public function chainedColumns(): array
    {
        return ['subject', 'client_id', 'act', 'scopes', 'claims', 'authorization_details', 'token_shape'];
    }
}
