<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Precis;

/**
 * RFC 5892 Appendix A.7 to A.9, the rules evaluated "For All Characters": one verdict for every occurrence of the code
 * point in a string, which the class therefore asks once per string.
 */
interface WholeStringRuleInterface extends ContextualRuleInterface
{
}
