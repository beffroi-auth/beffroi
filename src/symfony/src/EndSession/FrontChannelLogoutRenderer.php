<?php

declare(strict_types=1);

namespace Beffroi\Bundle\EndSession;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Application\EndSession\FrontChannelLogout;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutPage;
use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Symfony\Component\HttpFoundation\Response;

/**
 * Front-Channel Logout 1.0 §2: the page a browser is given once a session has ended, one frame per
 * client that registered a URI. The module says what the page must contain and what its
 * Content-Security-Policy is (FrontChannelLogoutPage), the bundle renders it from a template an
 * application may override and adds the headers every response of the interaction plane carries, the
 * "no-store" of §2 among them.
 */
final readonly class FrontChannelLogoutRenderer implements LogoutChannelInterface
{
    public const string TEMPLATE = 'front_channel_logout.html.twig';

    public function __construct(
        private FrontChannelLogout $logout,
        private InteractionPages $pages,
    ) {
    }

    public function channel(): LogoutChannel
    {
        return LogoutChannel::FrontChannel;
    }

    /**
     * @param list<AuthenticationSession> $sessions the sessions ended
     * @param string|null $continueTo the post_logout_redirect_uri of the request, when it named one, or
     *                                where a chain of SAML logout is resumed (beffroi/saml S-35)
     *
     * @return Response|null null when no client of the sessions registered a URI, and the logout answers
     *                       as it did before this page existed
     */
    public function render(array $sessions, ?string $continueTo): ?Response
    {
        $page = $this->logout->pageFor($sessions, $continueTo);
        if ($page === null) {
            return null;
        }

        return $this->pages->render(
            self::TEMPLATE,
            [
                'frames' => $page->frames,
                'continue_to' => $page->continueTo,
                'wait' => FrontChannelLogoutPage::WAIT,
                'script' => FrontChannelLogoutPage::SCRIPT,
            ],
            headers: [
                'Content-Security-Policy' => $page->contentSecurityPolicy(),
            ],
        );
    }
}
