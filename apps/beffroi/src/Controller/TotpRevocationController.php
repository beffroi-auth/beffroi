<?php

declare(strict_types=1);

namespace App\Controller;

use Beffroi\Core\Domain\Author\ThePerson;
use App\Http\Account\AsksForARecentProofInterface;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final readonly class TotpRevocationController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor_revoke';

    public const string CSRF_TOKEN_ID = 'beffroi_two_factor_revoke';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private ActiveTotp $activeTotp,
        private CredentialRevocation $revocation,
        private InteractionPages $pages,
    ) {
    }

    public function comesBackTo(): string
    {
        return AccountTwoFactorController::ROUTE;
    }

    #[Route('/account/two-factor/revoke', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $totp = $this->activeTotp->of($session->user) ?? throw new NotFoundHttpException('No authenticator app is set up.');
        $this->revocation->revoke($totp, new ThePerson(), $this->contexts->fromRequest($request));

        return $this->pages->afterTheForm(AccountTwoFactorController::ROUTE);
    }
}
