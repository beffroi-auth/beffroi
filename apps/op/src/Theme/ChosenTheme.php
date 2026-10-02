<?php

declare(strict_types=1);

namespace App\Theme;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RequestStack;
use function time;

/**
 * The theme of whoever is in front of the pages, read and written on one cookie (issue #447).
 *
 * Read on the server and not in a script, so that a page is rendered in the theme it was asked for and
 * never shows the other one first. It is a preference and not a credential: a forged choice changes a
 * colour, which is why it travels without a token and stays on the requests of this browser.
 */
final readonly class ChosenTheme
{
    public const string COOKIE = 'heidi_theme';

    /**
     * A year: a visitor who said once is not asked again, and a browser that never comes back drops it.
     */
    public const int LIFETIME = 31_536_000;

    public function __construct(
        private RequestStack $requests,
    ) {
    }

    public function current(): Theme
    {
        return Theme::ofChoice($this->requests->getCurrentRequest()?->cookies->getString(self::COOKIE));
    }

    /**
     * No script reads it (HttpOnly), it does not leave the requests of this browser (SameSite=Lax), and
     * the issuer is served over TLS, so it is never sent in clear (Secure).
     */
    public function cookie(Theme $theme): Cookie
    {
        return Cookie::create(
            self::COOKIE,
            $theme->value,
            time() + self::LIFETIME,
            '/',
            null,
            true,
            true,
            false,
            Cookie::SAMESITE_LAX,
        );
    }
}
