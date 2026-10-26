<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Http\Account\AsksForARecentProofInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Application\Totp\BackupCodesRenewal;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Another set of backup codes for the second factor of the signed-in person (architecture §5.2): the
 * codes they had stop working at that instant, and the new ones are shown this once.
 *
 * **It answers with the page and not with a redirection**, unlike every other form of these pages: what
 * it has to give is the codes themselves, and codes kept to be shown after a redirection would be codes
 * written to a session. It is the same answer the last step of an enrolment gives, for the same reason.
 *
 * A person who holds no second factor has none to renew and is not found; a person of a federated domain is
 * drawn none (decision 0029), and comes back to the page saying so.
 *
 * **A session alone does not post it** (AsksForARecentProofInterface): it invalidates the codes somebody
 * wrote down, which is as many ways in taken away.
 */
#[AsController]
final readonly class BackupCodesRenewalController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor_backup_codes';

    public const string CSRF_TOKEN_ID = 'beffroi_backup_codes_renew';

    /**
     * A person of a federated domain, for whom no backup code is drawn (decision 0029, beffroi/saml S-63).
     */
    public const string FEDERATED_DOMAIN = 'federated_domain';

    public function __construct(
        private AccountAccess $account,
        private ActiveTotp $totp,
        private BackupCodesRenewal $renewal,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private WhatWasRefused $refusals,
    ) {
    }

    /**
     * The page of the second factor, which holds the button this answers.
     */
    public function comesBackTo(): string
    {
        return AccountTwoFactorController::ROUTE;
    }

    #[Route('/account/two-factor/backup-codes', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $totp = $this->totp->of($session->user);
        if ($totp === null) {
            throw new NotFoundHttpException('No second factor to renew the backup codes of.');
        }

        try {
            $codes = $this->renewal->renew($totp, $this->contexts->fromRequest($request));
        } catch (CredentialEnrolmentFailedException) {
            // what the page offers nobody of a federated domain, refused to a post written by hand
            $this->refusals->keep($request, self::FEDERATED_DOMAIN);

            return $this->pages->afterTheForm(AccountTwoFactorController::ROUTE);
        }

        return $this->pages->render('account/backup_codes.html.twig', [
            'user' => $session->user,
            'backup_codes' => $codes,
        ]);
    }
}
