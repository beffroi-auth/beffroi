<?php

declare(strict_types=1);

namespace App\Controller;

use Beffroi\Core\Domain\Author\ThePerson;
use function array_find;
use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use Beffroi\Oidc\Application\Consent\ConsentRevocation;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The consent is found in the user's own list: somebody else's cannot be taken back.
 */
#[AsController]
final readonly class ConsentRevocationController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_consents_revoke';

    public const string CSRF_TOKEN_ID = 'beffroi_consent_revoke';

    public function __construct(
        private AccountAccess $account,
        private ActiveConsentsInterface $consents,
        private ConsentRevocation $revocation,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
    ) {
    }

    #[Route(
        '/account/consents/{id}/revoke',
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
        $consent = array_find(
            $this->consents->activeOf($session->user),
            static fn (Consent $consent): bool => $consent->id->toRfc4122() === $id,
        );
        if ($consent === null) {
            throw new NotFoundHttpException('No such consent.');
        }
        $this->revocation->revoke($consent, new ThePerson(), $this->contexts->fromRequest($request));

        return $this->pages->afterTheForm(AccountConsentsController::ROUTE);
    }
}
