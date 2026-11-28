<?php

declare(strict_types=1);

namespace App\Doctor;

use App\Doctrine\PersonalData\BlindIndexDerivations;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Port\AmbientTenantInterface;
use IntlChar;
use function sprintf;
use Throwable;

/**
 * What a password may hold follows the version of Unicode the process reads (RFC 8264 §13.4, decision 0065): the
 * version the last beffroi:user:reindex of the tenant recorded is the one of the last build that started, and a
 * process under another one, of a deployment that rolls or of a console outside the image, may refuse a password
 * posed under it.
 */
final readonly class PasswordsUnderTheUnicodeOfTheBuild implements CheckInterface
{
    public const string ABOUT = 'Passwords: admitted under the Unicode of this build';

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
            return Finding::red(self::ABOUT, [sprintf(
                'The version of Unicode the tenant was last indexed under cannot be read: %s',
                ExceptionTrail::of($exception),
            )]);
        }
        if ($recorded !== null && $recorded->unicodeVersion !== IntlChar::UNICODE_VERSION) {
            return Finding::red(self::ABOUT, [
                sprintf(
                    'The tenant "%s" was last indexed under Unicode %s, and this process reads Unicode %s: a password posed under the one may be refused under the other.',
                    $tenant->slug,
                    $recorded->unicodeVersion,
                    IntlChar::UNICODE_VERSION,
                ),
                'What makes it green: every process of the deployment, the console included, on the same image.',
            ]);
        }

        return Finding::green(
            self::ABOUT,
            $recorded === null
                ? sprintf('This process reads Unicode %s, and the tenant "%s" records no version yet.', IntlChar::UNICODE_VERSION, $tenant->slug)
                : sprintf('This process reads Unicode %s, as the tenant "%s" was last indexed under.', IntlChar::UNICODE_VERSION, $tenant->slug),
        );
    }
}
