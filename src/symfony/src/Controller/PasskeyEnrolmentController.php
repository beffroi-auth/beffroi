<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Bundle\Http\Account\AsksForARecentProofInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Http\PasskeyOptionsStore;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Passkey\PasskeyEnrolment;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use function mb_strlen;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use function trim;

/**
 * The attestation of a new passkey, posted by the page of the account with the name the user gave it and
 * the CSRF token (architecture §5.2): verified by the enrolment of the core against the options this
 * browser was given for this user; the page comes back with the passkey listed, or with what went wrong.
 *
 * It answers with a redirection whether the ceremony was completed or refused (issue #481): a browser
 * reloading the page it comes back to does not present the same thing again, and what was refused crosses
 * the redirection in the session (WhatWasRefused).
 *
 * **A session alone does not post it** (AsksForARecentProofInterface): adding a credential is adding a
 * way in, so a browser whose newest proof is older than the window is sent to the login of the firewall
 * and the ceremony is begun again from the page.
 */
#[AsController]
final readonly class PasskeyEnrolmentController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_passkeys_enrol';

    public const string CSRF_TOKEN_ID = 'beffroi_passkey_enrol';

    public const string NAME_PARAMETER = 'name';

    public const string ATTESTATION_PARAMETER = '_passkey';

    public const string INVALID_NAME = 'invalid_name';

    public const string NO_CEREMONY = 'no_ceremony';

    public const string REFUSED = 'refused';

    /**
     * A person of a federated domain, for whom no passkey is posed (decision 0029, beffroi/saml S-63).
     */
    public const string FEDERATED_DOMAIN = 'federated_domain';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private PasskeyEnrolment $enrolment,
        private PasskeyOptionsStore $options,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
        private FederatedDomains $federated,
    ) {
    }

    /**
     * The page of the passkeys, which holds the ceremony this completes.
     */
    public function comesBackTo(): string
    {
        return AccountPasskeysController::ROUTE;
    }

    #[Route('/account/passkeys', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        // before the ceremony goes on: what the page offers nobody of a federated domain is refused to a post written
        // by hand, which the enrolment of the core refuses too, and this says why
        if (! $this->federated->admitsLocalCredentials($user)) {
            return $this->refused($request, self::FEDERATED_DOMAIN);
        }
        $name = trim($request->request->getString(self::NAME_PARAMETER));
        if ($name === '' || mb_strlen($name) > PasskeyCredential::NAME_MAX_LENGTH) {
            return $this->refused($request, self::INVALID_NAME);
        }
        $attestation = $request->request->getString(self::ATTESTATION_PARAMETER);
        $options = $this->options->takeCreation($request->getSession(), $user->id);
        if ($attestation === '' || $options === null) {
            return $this->refused($request, self::NO_CEREMONY);
        }
        try {
            $this->enrolment->complete($user, $name, $options, $attestation, $this->contexts->fromRequest($request));
        } catch (CredentialEnrolmentFailedException) {
            return $this->refused($request, self::REFUSED);
        }

        return $this->pages->afterTheForm(AccountPasskeysController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(AccountPasskeysController::ROUTE);
    }
}
