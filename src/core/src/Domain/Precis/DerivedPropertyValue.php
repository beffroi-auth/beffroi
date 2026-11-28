<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 8264 §8, without ID_PVAL and FREE_DIS, which the specification never assigns.
 */
enum DerivedPropertyValue: string
{
    case Pvalid = 'PVALID';

    /**
     * "ID_DIS or FREE_PVAL": refused by the IdentifierClass, admitted by the FreeformClass.
     */
    case FreePval = 'FREE_PVAL';

    case Contextj = 'CONTEXTJ';

    case Contexto = 'CONTEXTO';

    case Disallowed = 'DISALLOWED';

    case Unassigned = 'UNASSIGNED';
}
