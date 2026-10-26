<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

/**
 * A session of the signed-in user ended from the page of the account (architecture §5.2): it authenticates
 * nothing afterwards, and what it opened for a relying party is reached by the back-channel exactly as a
 * logout reaches it, because the end of a session is one act of the core and says so once
 * (AuthenticationSessionEnded). Someone else's session is not found.
 *
 * Ending the session of the browser reading the page is not the same act as ending another: that browser
 * is signed out here, the way the end session endpoint signs one out, the clients of OpenID Connect of
 * the session that registered a front-channel logout URI loaded by its page and the SAML service
 * providers it signed in told in turn (beffroi/saml S-29, S-35), and it is told so.
 *
 * **A session alone reaches it** (ReachedOnTheSessionAloneInterface): ending a session is what a person
 * does because they fear that session, and asking them to prove themselves first would be asking them to
 * type a password on the browser they are worried about. It is the one gesture of these pages that only
 * ever locks an attacker out.
 */
#[AsController]
final readonly class AccountSessionRevocationController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_sessions_revoke';

    public const string CSRF_TOKEN_ID = 'beffroi_session_revoke';

    public function __construct(
        private AccountAccess $account,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionTerminator $terminator,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private LogoutChainPages $logoutChain,
    ) {
    }

    #[Route(
        '/account/sessions/{id}/revoke',
        name: self::ROUTE,
        methods: ['POST'],
        requirements: [
            'id' => '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        ],
    )]
    public function __invoke(Request $request, string $id): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $ended = $this->sessions->find(Uuid::fromString($id));
        if (! $ended instanceof AuthenticationSession || ! $ended->user->id->equals($session->user->id) || $ended->hasEnded()) {
            throw new NotFoundHttpException('No such session.');
        }
        $this->terminator->end($ended, SessionEnd::User, $this->contexts->fromRequest($request));
        if (! $ended->id->equals($session->id)) {
            return $this->pages->afterTheForm(AccountSessionsController::ROUTE);
        }
        $this->browser->unbind($request->getSession());

        return $this->logoutChain->begin($ended->tenant, [$ended], null) ?? $this->pages->render('logged_out.html.twig', ['logged_out' => true]);
    }
}
