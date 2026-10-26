<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_key_exists;
use function array_filter;
use function array_slice;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use DateTimeImmutable;
use function is_array;
use function is_int;
use function is_string;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * The logins of a browser whose page passed the step of the address (beffroi/saml S-61): when the tenant federates a
 * domain, the login page asks for the address first, and shows the usual page once an address of no federated domain,
 * or a username, was typed for that login. Kept in the HTTP session of that browser and never in a URL, by interaction,
 * and under a key of its own for the login a page of the provider waits for (LoginTarget), which no identifier of an
 * interaction can be; at most eight, the oldest forgotten first, as the requests that wait for a login are kept
 * (WaitingSignOns); what was typed goes where the field of the username of the usual page reads it
 * (AuthenticationUtils::getLastUsername()).
 *
 * An address of a federated domain, typed at the page of the address or hinted by the client, is kept apart, by the
 * same keys and under the same bound, for the sign-on the discovery sends the browser to, which takes it once and
 * carries it to a provider that reads one (S-68): never in a URL, so that no page of another site hands a sign-on an
 * address of its choosing. It is held in clear, as what was typed is, and no longer than its login needs: taken by
 * that sign-on, dropped when the interaction ends (BrowserSession::forget()) or the page that waited is served
 * (LoginTarget::forget()), and never read once the ten minutes of its wait are over, an address past them dropped
 * whenever the addresses of the browser are read or written, as a request to a provider is (UpstreamSignOns).
 */
final readonly class LoginAddresses
{
    public const string SESSION_KEY = '_beffroi_login_addresses';

    public const string SENT_SESSION_KEY = '_beffroi_login_addresses_sent';

    /**
     * beffroi/saml S-68, section 7: the wait of a request for a login (S-18), which the address kept for a sign-on
     * waits no longer than.
     */
    public const int SENT_WAIT = 600;

    public const int MAX_KEPT = 8;

    /**
     * The login a page of the provider waits for, which no identifier of an interaction is: those are base64url.
     */
    private const string WAITING_PAGE = ':page';

    /**
     * @param Interaction|null $interaction null for the login a page of the provider waits for
     */
    public function pass(SessionInterface $httpSession, ?Interaction $interaction, string $identifier): void
    {
        $passed = self::passedOnes($httpSession);
        $key = self::key($interaction);
        unset($passed[$key]);
        $passed[$key] = true;
        $httpSession->set(self::SESSION_KEY, array_slice($passed, -self::MAX_KEPT, preserve_keys: true));
        $httpSession->set(SecurityRequestAttributes::LAST_USERNAME, $identifier);
    }

    public function passed(SessionInterface $httpSession, ?Interaction $interaction): bool
    {
        return array_key_exists(self::key($interaction), self::passedOnes($httpSession));
    }

    /**
     * Back to the step of the address, for another one: what was typed for that login forgotten, the address kept for
     * its sign-on with it.
     */
    public function forget(SessionInterface $httpSession, ?Interaction $interaction): void
    {
        $key = self::key($interaction);
        $passed = self::passedOnes($httpSession);
        if (array_key_exists($key, $passed)) {
            unset($passed[$key]);
            $httpSession->set(self::SESSION_KEY, $passed);
        }
        $sent = self::sentOnes($httpSession);
        if (array_key_exists($key, $sent)) {
            unset($sent[$key]);
            $httpSession->set(self::SENT_SESSION_KEY, $sent);
        }
    }

    /**
     * S-68: the address of a federated domain the discovery sends to the sign-on of its provider, kept for that sign-on,
     * as it was given.
     *
     * @param Interaction|null $interaction null for the login a page of the provider waits for
     */
    public function sendOn(SessionInterface $httpSession, ?Interaction $interaction, string $address, DateTimeImmutable $now): void
    {
        $sent = self::waitingOnes($httpSession, $now);
        $key = self::key($interaction);
        unset($sent[$key]);
        $sent[$key] = [
            'address' => $address,
            'sent_at' => $now->getTimestamp(),
        ];
        $httpSession->set(self::SENT_SESSION_KEY, array_slice($sent, -self::MAX_KEPT, preserve_keys: true));
    }

    /**
     * S-68: the address kept for the sign-on of that login, forgotten as it is read, so that a sign-on the discovery did
     * not send the browser to, the request sent once more among them, carries none; null when none is kept, or when
     * the one kept has waited longer than SENT_WAIT.
     */
    public function takeSent(SessionInterface $httpSession, ?Interaction $interaction, DateTimeImmutable $now): ?string
    {
        $sent = self::waitingOnes($httpSession, $now);
        $key = self::key($interaction);
        $address = isset($sent[$key]) ? $sent[$key]['address'] : null;
        unset($sent[$key]);
        $httpSession->set(self::SENT_SESSION_KEY, $sent);

        return $address;
    }

    private static function key(?Interaction $interaction): string
    {
        return $interaction->id ?? self::WAITING_PAGE;
    }

    /**
     * @return array<string, true>
     */
    private static function passedOnes(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $passed = [];
        foreach ($stored as $interaction => $true) {
            if (is_string($interaction) && $true === true) {
                $passed[$interaction] = true;
            }
        }

        return $passed;
    }

    /**
     * The addresses kept whose wait is not over at that instant.
     *
     * @return array<string, array{address: string, sent_at: int}>
     */
    private static function waitingOnes(SessionInterface $httpSession, DateTimeImmutable $now): array
    {
        return array_filter(
            self::sentOnes($httpSession),
            static fn (array $sent): bool => ($sent['sent_at'] + self::SENT_WAIT) >= $now->getTimestamp(),
        );
    }

    /**
     * What the HTTP session holds, an entry that is no address kept left out.
     *
     * @return array<string, array{address: string, sent_at: int}>
     */
    private static function sentOnes(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SENT_SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $sent = [];
        foreach ($stored as $login => $entry) {
            $address = is_array($entry) ? $entry['address'] ?? null : null;
            $sentAt = is_array($entry) ? $entry['sent_at'] ?? null : null;
            if (is_string($login) && is_string($address) && is_int($sentAt)) {
                $sent[$login] = [
                    'address' => $address,
                    'sent_at' => $sentAt,
                ];
            }
        }

        return $sent;
    }
}
