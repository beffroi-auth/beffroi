<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use function array_filter;
use function array_slice;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use DateTimeImmutable;
use function hash_equals;
use function is_array;
use function is_int;
use function is_string;
use function random_bytes;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The references a sign-on at an upstream identity provider starts under (beffroi/saml, spec/saml.md S-51): drawn when
 * the login page sends the browser to the sign-on, by the step of the address, which posts under its form token
 * (S-61), or by the "login_hint" that skips it (S-62), 32 bytes of random_bytes() in the URL of that redirection alone;
 * kept in the HTTP session of that browser by interaction, and under a key of its own for the login a page of the
 * provider waits for (LoginTarget), which no identifier of an interaction can be, with the provider the discovery
 * chose and the instant it was drawn; at most eight, the oldest forgotten first, a login drawing another forgetting
 * the one before, and a reference past its life dropped whenever the references of the browser are read or written,
 * as LoginAddresses keeps the address sent on with it.
 *
 * The sign-on takes it once: forgotten at its first presentation whatever was presented, compared with hash_equals(),
 * for the provider it was drawn for and within LIFE of its drawing. A page of another site can send the browser to the
 * sign-on, the session cookie going with a top-level navigation, but reads none of them, and starts nothing.
 *
 * @phpstan-type Kept array{reference: string, identity_provider: string, issued_at: int}
 */
final readonly class UpstreamSignOnReferences
{
    public const string SESSION_KEY = '_beffroi_saml_upstream_sign_on_references';

    public const int MAX_KEPT = 8;

    /**
     * Section 7: the life of a reference, in seconds, the redirection that carries it being followed at once.
     */
    public const int LIFE = 60;

    private const int BYTES = 32;

    /**
     * The login a page of the provider waits for, which no identifier of an interaction is: those are base64url.
     */
    private const string WAITING_PAGE = ':page';

    /**
     * The reference of the sign-on of that login at that provider, which the redirection to the sign-on carries.
     *
     * @param Interaction|null $interaction null for the login a page of the provider waits for
     * @param string $identityProvider the entity ID of the provider the discovery chose
     */
    public function issue(SessionInterface $httpSession, ?Interaction $interaction, string $identityProvider, DateTimeImmutable $now): string
    {
        $reference = Base64Url::encode(random_bytes(self::BYTES));
        $kept = self::living($httpSession, $now);
        $key = self::key($interaction);
        unset($kept[$key]);
        $kept[$key] = [
            'reference' => $reference,
            'identity_provider' => $identityProvider,
            'issued_at' => $now->getTimestamp(),
        ];
        $httpSession->set(self::SESSION_KEY, array_slice($kept, -self::MAX_KEPT, preserve_keys: true));

        return $reference;
    }

    /**
     * Whether the sign-on of that login at that provider is presented the reference drawn for it, within its life;
     * the reference forgotten whatever was presented, so that it starts one sign-on at most.
     *
     * @param Interaction|null $interaction null for the login a page of the provider waits for
     */
    public function take(
        SessionInterface $httpSession,
        ?Interaction $interaction,
        string $identityProvider,
        string $presented,
        DateTimeImmutable $now,
    ): bool {
        $kept = self::living($httpSession, $now);
        $key = self::key($interaction);
        $entry = $kept[$key] ?? null;
        unset($kept[$key]);
        $httpSession->set(self::SESSION_KEY, $kept);

        return $entry !== null && hash_equals($entry['reference'], $presented) && $entry['identity_provider'] === $identityProvider;
    }

    private static function key(?Interaction $interaction): string
    {
        return $interaction->id ?? self::WAITING_PAGE;
    }

    /**
     * The references kept whose life is not over at that instant.
     *
     * @return array<string, Kept>
     */
    private static function living(SessionInterface $httpSession, DateTimeImmutable $now): array
    {
        return array_filter(
            self::kept($httpSession),
            static fn (array $kept): bool => ($kept['issued_at'] + self::LIFE) >= $now->getTimestamp(),
        );
    }

    /**
     * What the HTTP session holds, an entry that is no reference kept left out.
     *
     * @return array<string, Kept>
     */
    private static function kept(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $kept = [];
        foreach ($stored as $login => $entry) {
            $reference = is_array($entry) ? $entry['reference'] ?? null : null;
            $identityProvider = is_array($entry) ? $entry['identity_provider'] ?? null : null;
            $issuedAt = is_array($entry) ? $entry['issued_at'] ?? null : null;
            if (is_string($login) && is_string($reference) && is_string($identityProvider) && is_int($issuedAt)) {
                $kept[$login] = [
                    'reference' => $reference,
                    'identity_provider' => $identityProvider,
                    'issued_at' => $issuedAt,
                ];
            }
        }

        return $kept;
    }
}
