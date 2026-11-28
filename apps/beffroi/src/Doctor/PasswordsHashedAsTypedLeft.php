<?php

declare(strict_types=1);

namespace App\Doctor;

use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Core\Port\CanCountPasswordsHashedAsTypedInterface;
use function sprintf;
use Throwable;

/**
 * How many passwords of the tenant are still hashed as they were typed, before the OpaqueString profile (decision 0065):
 * every sign-in of the tenant verifies two forms until the last is replaced, which no fault is, so the point stays green.
 */
final readonly class PasswordsHashedAsTypedLeft implements CheckInterface
{
    public const string ABOUT = 'Passwords: hashed as typed before the profile';

    public function __construct(
        private AmbientTenantInterface $tenants,
        private CanCountPasswordsHashedAsTypedInterface $hashedAsTyped,
    ) {
    }

    public function finding(): Finding
    {
        try {
            $tenant = $this->tenants->provide();
            $count = $this->hashedAsTyped->countIn($tenant);
        } catch (Throwable $exception) {
            return Finding::red(self::ABOUT, [sprintf('The passwords hashed as typed cannot be counted: %s', ExceptionTrail::of($exception))]);
        }

        return Finding::green(
            self::ABOUT,
            $count === 0
                ? sprintf('No password of the tenant "%s" is hashed as typed: a sign-in verifies one form.', $tenant->slug)
                : sprintf(
                    '%d password(s) of the tenant "%s" are hashed as typed, before the profile: every sign-in of the tenant verifies two forms until the last is replaced at the sign-in of its person.',
                    $count,
                    $tenant->slug,
                ),
        );
    }
}
