<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Model\ModelEntityId;

/**
 * The last segment of the URL of the metadata given to one upstream identity provider (beffroi/saml, spec/saml.md
 * S-65): its entity ID in the base64url of RFC 4648 §5 without padding. An entity ID is a URI, whose "/", "?", "#" and
 * "%" a path segment would carry percent-encoded and a server or a proxy on the way merges or decodes; base64url is one
 * segment of letters, digits, "-" and "_", read back without a table of the providers, so that an operator writes the
 * URL from the entity ID alone and the route reads the entity ID from the URL alone.
 */
final class IdentityProviderSegment
{
    /**
     * What the route requires of the segment: base64url, at most the 1 366 characters of the 1 024 octets of the
     * longest entity ID (M-6), which the router refuses otherwise before anything is read.
     */
    public const string REQUIREMENT = '[A-Za-z0-9_-]{1,1366}';

    private function __construct()
    {
    }

    public static function of(string $entityId): string
    {
        return Base64Url::encode($entityId);
    }

    /**
     * The entity ID the segment names, null when it is not base64url, is not the one way of writing it, so that a
     * provider has one URL and not several that a cache or a rule at the edge would tell apart, or its value is no
     * entity ID of an identity provider (M-6).
     */
    public static function entityIdOf(string $segment): ?string
    {
        $entityId = Base64Url::decode($segment);
        if ($entityId === null || Base64Url::encode($entityId) !== $segment) {
            return null;
        }

        try {
            return ModelEntityId::ofIdentityProvider($entityId);
        } catch (InvalidArgumentException) {
            return null;
        }
    }
}
