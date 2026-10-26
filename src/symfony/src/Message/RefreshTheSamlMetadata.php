<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * The metadata of every SAML peer of the tenant read again, its service providers and its upstream identity providers
 * (beffroi/saml, spec/saml.md sections 6.2 and 6.10): recurring and idempotent, a document read again as it was
 * accepted writing nothing, and a refusal keeping the document accepted until the next tick.
 */
final readonly class RefreshTheSamlMetadata implements Command
{
}
