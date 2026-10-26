<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_slice;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use function is_array;
use function is_string;
use function random_bytes;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The SAML requests a browser sent that wait for its login (beffroi/saml, spec/saml.md S-18, section 6.4 step 3): kept
 * in the HTTP session of that browser and never in a URL, each under a reference of 32 bytes of random_bytes(), at most
 * eight, the oldest forgotten first, as the interactions a browser began are (BrowserSession). The reference is what
 * the login of the provider sends the browser back with; another browser holds none of them, and a request is
 * forgotten once it is answered.
 */
final readonly class WaitingSignOns
{
    public const string SESSION_KEY = '_beffroi_saml_sign_ons';

    public const int MAX_WAITING = 8;

    /**
     * @return string the reference the request waits under
     */
    public function keep(SessionInterface $httpSession, Tenant $tenant, SignOnRequest $request): string
    {
        $reference = Base64Url::encode(random_bytes(32));
        $waiting = self::waiting($httpSession);
        $waiting[$reference] = [
            'tenant' => $tenant->id->toRfc4122(),
            'request' => $request->toDocument(),
        ];
        $httpSession->set(self::SESSION_KEY, array_slice($waiting, -self::MAX_WAITING, preserve_keys: true));

        return $reference;
    }

    /**
     * The request waiting under that reference in this browser for this tenant, null otherwise, without telling which.
     */
    public function find(SessionInterface $httpSession, Tenant $tenant, string $reference): ?SignOnRequest
    {
        $waiting = self::waiting($httpSession)[$reference] ?? null;
        if ($waiting === null || $waiting['tenant'] !== $tenant->id->toRfc4122()) {
            return null;
        }
        try {
            return SignOnRequest::fromDocument($waiting['request']);
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    public function forget(SessionInterface $httpSession, string $reference): void
    {
        $waiting = self::waiting($httpSession);
        unset($waiting[$reference]);
        if ($waiting === []) {
            $httpSession->remove(self::SESSION_KEY);

            return;
        }
        $httpSession->set(self::SESSION_KEY, $waiting);
    }

    /**
     * @return array<string, array{tenant: string, request: array<array-key, mixed>}>
     */
    private static function waiting(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $waiting = [];
        foreach ($stored as $reference => $entry) {
            if (is_string($reference) && is_array($entry) && is_string($entry['tenant'] ?? null) && is_array($entry['request'] ?? null)) {
                $waiting[$reference] = [
                    'tenant' => $entry['tenant'],
                    'request' => $entry['request'],
                ];
            }
        }

        return $waiting;
    }
}
