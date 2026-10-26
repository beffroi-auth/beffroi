<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Bundle\Http\Account\AsksForARecentProofInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Core\Application\Totp\TotpEnrolment;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The first step of the enrolment of an authenticator app (architecture §5.2): the provisioning drawn
 * by the enrolment of the core for the signed-in user, kept sealed in the session of this browser for
 * the code that comes back, and shown as a QR code and as a key. A user who holds an app already is
 * refused, they remove it first; nothing is written until the first code holds.
 *
 * It answers with a redirection whether the step went through or was refused (issue #481), so that a
 * browser reloading does not post it again; what was refused crosses it in the session (WhatWasRefused).
 *
 * **A session alone does not post it** (AsksForARecentProofInterface): what this step draws becomes a way
 * in the moment the first code holds.
 */
#[AsController]
final readonly class TotpEnrolmentBeginController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor_begin';

    public const string CSRF_TOKEN_ID = 'beffroi_two_factor_begin';

    public const string ALREADY_ENROLLED = 'already_enrolled';

    /**
     * A person of a federated domain, for whom no authenticator app is set up (decision 0029, beffroi/saml S-63).
     */
    public const string FEDERATED_DOMAIN = 'federated_domain';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private TotpEnrolment $enrolment,
        private TotpProvisioningStore $provisionings,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
        private FederatedDomains $federated,
    ) {
    }

    /**
     * The page of the second factor, which holds the button this answers.
     */
    public function comesBackTo(): string
    {
        return AccountTwoFactorController::ROUTE;
    }

    #[Route('/account/two-factor/begin', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        // before a secret is drawn: what the page offers nobody of a federated domain is refused to a post written by
        // hand, which the enrolment of the core refuses too, and this says why
        if (! $this->federated->admitsLocalCredentials($user)) {
            $this->refusals->keep($request, self::FEDERATED_DOMAIN);

            return $this->pages->afterTheForm(AccountTwoFactorController::ROUTE);
        }
        try {
            $provisioning = $this->enrolment->begin($user);
        } catch (CredentialEnrolmentFailedException) {
            $this->refusals->keep($request, self::ALREADY_ENROLLED);

            return $this->pages->afterTheForm(AccountTwoFactorController::ROUTE);
        }
        $this->provisionings->store($request->getSession(), $user, $provisioning, $this->contexts->fromRequest($request)->receivedAt);

        return $this->pages->afterTheForm(AccountTwoFactorEnrolmentController::ROUTE);
    }
}
