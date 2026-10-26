<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;

/**
 * The salt of every tenant under test (spec/saml.md S-13).
 */
final readonly class FixedSalt implements PersistentIdentifierSaltInterface
{
    public const string SALT = 'the salt of the tenant under test';

    public function saltOf(Tenant $tenant): string
    {
        return self::SALT;
    }
}
