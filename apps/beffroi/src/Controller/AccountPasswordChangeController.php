<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\AsksForARecentProofInterface;
use App\Http\Account\BreachedPasswordDemand;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use App\Http\WhatWasRefused;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Beffroi\Core\Exception\PasswordRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final readonly class AccountPasswordChangeController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_password_change';

    public const string CSRF_TOKEN_ID = 'beffroi_password_change';

    public const string IN_USE_PARAMETER = 'current_password';

    public const string POSED_PARAMETER = 'new_password';

    public const string POSED_AGAIN_PARAMETER = 'new_password_again';

    public const string NOT_CONFIRMED = 'not_confirmed';

    public function __construct(
        private AccountAccess $account,
        private PasswordChange $change,
        private OtherSessionsTermination $others,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private BreachedPasswordDemand $demands,
        private InteractionPages $pages,
    ) {
    }

    public function comesBackTo(): string
    {
        return AccountPasswordController::ROUTE;
    }

    #[Route('/account/password', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        try {
            $posed = new PlainPassword($request->request->getString(self::POSED_PARAMETER), PasswordLength::under($session->user->tenant->loginFloor));
        } catch (PasswordRefusedException $exception) {
            return $this->refused($request, $exception->refusal->value);
        }
        if (! $posed->confirmedBy($request->request->getString(self::POSED_AGAIN_PARAMETER))) {
            return $this->refused($request, self::NOT_CONFIRMED);
        }
        $context = $this->contexts->fromRequest($request);

        try {
            $this->change->change(
                $session->user,
                $request->request->getString(self::IN_USE_PARAMETER),
                $posed,
                $context,
            );
        } catch (PasswordRefusedException|PasswordChangeRefusedException $exception) {
            return $this->refused($request, $exception->refusal->value);
        }
        $this->others->endEveryOther($session, $context);

        return $this->demands->answered($request->getSession()) ?? $this->pages->afterTheForm(AccountPasswordController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(AccountPasswordController::ROUTE);
    }
}
