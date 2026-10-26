<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CanPageCredentialsInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of the passkeys of a user (architecture §5.2), rendered by the controller that shows it and by
 * the ones that come back to it with what went wrong.
 */
final readonly class PasskeysPage
{
    public function __construct(
        private CanPageCredentialsInterface $credentials,
        private AskedPage $asked,
        private AskedPeriod $period,
        private InteractionPages $pages,
        private FederatedDomains $federated,
    ) {
    }

    /**
     * @param string|null $error a code the template translates
     */
    public function render(User $user, ?string $error = null, int $status = Response::HTTP_OK): Response
    {
        $period = $this->period->asked($user);

        return $this->pages->render(
            'account/passkeys.html.twig',
            [
                'user' => $user,
                'passkeys' => $this->credentials->pageOfCredentials($user, PasskeyCredential::class, $this->asked->asked(), $period),
                'period' => $period,
                'error' => $error,
                // decision 0029, beffroi/saml S-63: no passkey is posed for a person of a federated domain
                'federated' => ! $this->federated->admitsLocalCredentials($user),
            ],
            $status,
        );
    }
}
