<?php

declare(strict_types=1);

namespace App\Doctor;

use App\Doctrine\PersonalData\BlindIndexDerivations;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\RecordedDerivation;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Port\AmbientTenantInterface;
use const DATE_ATOM;
use IntlChar;
use function sprintf;
use Throwable;

/**
 * Whether every person of the tenant is found by the enforced form of their username (RFC 8265 §3.3.4), from what the
 * last beffroi:user:reindex recorded: tags derived under other projections or under another version of Unicode, and the
 * persons it named, whose usernames the profile refuses or compares as one.
 */
final readonly class UsernamesComparedByTheirForm implements CheckInterface
{
    public const string ABOUT = 'Usernames: compared by their enforced form';

    public function __construct(
        private AmbientTenantInterface $tenants,
        private BlindIndexDerivations $derivations,
    ) {
    }

    public function finding(): Finding
    {
        try {
            $tenant = $this->tenants->provide();
            $recorded = $this->derivations->recorded($tenant);
        } catch (Throwable $exception) {
            return Finding::red(self::ABOUT, [sprintf('What the tags of the tenant were derived under cannot be read: %s', ExceptionTrail::of($exception))]);
        }
        if ($recorded?->isCurrent() !== true) {
            return Finding::red(self::ABOUT, [
                sprintf(
                    'The tags of the persons of the tenant "%s" were derived %s, and this build derives them under derivation %d and Unicode %s: a person whose username is not in its enforced form is found under it as written only, and no person is created or renamed.',
                    $tenant->slug,
                    self::under($recorded),
                    BlindIndexedColumns::DERIVATION,
                    IntlChar::UNICODE_VERSION,
                ),
                'What makes it green: "bin/console beffroi:user:reindex", which the image runs at its start.',
            ]);
        }
        if ($recorded->refused > 0 || $recorded->joined > 0) {
            return Finding::red(self::ABOUT, [
                sprintf(
                    'The reindex of %s named %d person(s) whose username RFC 8265 §3.3 refuses, who sign in under it as written until 1.0.0 and no later, and %d person(s) whose usernames it compares as one, whom no lookup finds.',
                    $recorded->derivedAt->format(DATE_ATOM),
                    $recorded->refused,
                    $recorded->joined,
                ),
                'What makes it green: "bin/console beffroi:user:rename <identifier> <username>" for each of them, then "bin/console beffroi:user:reindex".',
            ]);
        }

        return Finding::green(self::ABOUT, sprintf(
            'Every person of the tenant "%s" is found by the enforced form of their username, derivation %d under Unicode %s.',
            $tenant->slug,
            BlindIndexedColumns::DERIVATION,
            IntlChar::UNICODE_VERSION,
        ));
    }

    private static function under(?RecordedDerivation $recorded): string
    {
        return $recorded === null
            ? 'under no recorded derivation, as 0.1 left them'
            : sprintf('under derivation %d and Unicode %s', $recorded->derivation, $recorded->unicodeVersion);
    }
}
