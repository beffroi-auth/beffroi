<?php

declare(strict_types=1);

namespace App\Controller;

use Beffroi\Core\Domain\Author\ThePerson;
use App\Http\Account\AsksForARecentProofInterface;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

#[AsController]
final readonly class PasskeyRevocationController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_passkeys_revoke';

    public const string CSRF_TOKEN_ID = 'beffroi_passkey_revoke';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private CredentialRepositoryInterface $credentials,
        private CredentialRevocation $revocation,
        private InteractionPages $pages,
    ) {
    }

    public function comesBackTo(): string
    {
        return AccountPasskeysController::ROUTE;
    }

    #[Route(
        '/account/passkeys/{id}/revoke',
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
        $passkey = $this->credentials->find(Uuid::fromString($id));
        if (! $passkey instanceof PasskeyCredential || ! $passkey->user->id->equals($session->user->id)) {
            throw new NotFoundHttpException('No such passkey.');
        }
        $this->revocation->revoke($passkey, new ThePerson(), $this->contexts->fromRequest($request));

        return $this->pages->afterTheForm(AccountPasskeysController::ROUTE);
    }
}
