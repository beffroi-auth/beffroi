<?php

declare(strict_types=1);

namespace App\Controller;

use Beffroi\Core\Domain\Author\ThePerson;
use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\BrowserSession;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use App\Saml\LogoutChainPages;
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
 * Reached on the session alone: asking for a proof first would mean typing a password on a browser one fears.
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
        $this->terminator->end($ended, SessionEnd::User, new ThePerson(), $this->contexts->fromRequest($request));
        if (! $ended->id->equals($session->id)) {
            return $this->pages->afterTheForm(AccountSessionsController::ROUTE);
        }
        $this->browser->unbind($request->getSession());

        return $this->logoutChain->begin($ended->tenant, [$ended], null) ?? $this->pages->render('logged_out.html.twig', ['logged_out' => true]);
    }
}
