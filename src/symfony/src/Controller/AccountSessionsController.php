<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\SessionsPage;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where the signed-in user is signed in (architecture §5.2): the sessions open in their name, and the
 * button that ends one. A browser without a session of the core is told to sign in first. The button of
 * the session of this browser is answered with the SAML service providers of that session told in turn,
 * redirections of its submission, which the page names (beffroi/saml S-36).
 */
#[AsController]
final readonly class AccountSessionsController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_sessions';

    public function __construct(
        private AccountAccess $account,
        private SessionsPage $page,
        private LogoutChainPages $logoutChain,
    ) {
    }

    #[Route('/account/sessions', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        $this->logoutChain->mayEnd($request, $session);

        return $this->page->render($session);
    }
}
