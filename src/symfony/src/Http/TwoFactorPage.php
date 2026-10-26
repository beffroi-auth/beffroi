<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Application\Identity\FederatedDomains;
use function array_filter;
use function count;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Domain\Credential\BackupCode;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpProvisioning;
use Beffroi\Core\Domain\Identity\User;
use function implode;
use ParagonIE\ConstantTime\Base32;
use function str_split;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of the second factor of a user (architecture §5.2), in its three states: what the account
 * holds (an authenticator app or none), the enrolment in progress (the QR code, the key for a manual
 * entry, the first code), and the backup codes of an enrolment just completed, shown once. Rendered by
 * the controllers that show it and by the ones that come back to it with what went wrong.
 *
 * It offers setting one up only where the floor of the tenant admits a one-time code (issue #327), as the
 * login page offers the forms its tenant admits: a tenant that signs its users in by passkey refuses the
 * enrolment (TotpEnrolment), and a page that offered it anyway would be a button that always fails. Nor
 * does it offer one to a person of a federated domain (decision 0029), whom the enrolment refuses too.
 */
final readonly class TwoFactorPage
{
    public function __construct(
        private ActiveTotp $activeTotp,
        private QrCode $qrCode,
        private InteractionPages $pages,
        private FederatedDomains $federated,
    ) {
    }

    /**
     * @param string|null $error a code the template translates
     */
    public function render(User $user, ?string $error = null, int $status = Response::HTTP_OK): Response
    {
        $totp = $this->activeTotp->of($user);

        return $this->pages->render(
            'account/two_factor.html.twig',
            [
                'user' => $user,
                'totp' => $totp,
                'backup_codes_left' => $totp === null ? 0 : count(array_filter($totp->backupCodes, static fn (BackupCode $code): bool => ! $code->isSpent())),
                'admitted' => $user->tenant->loginFloor->admits([TotpCredential::method()]),
                // decision 0029, beffroi/saml S-63: no authenticator app is set up for a person of a federated domain
                'federated' => ! $this->federated->admitsLocalCredentials($user),
                'error' => $error,
            ],
            $status,
        );
    }

    /**
     * The key is the secret in base32 (RFC 4648 §6), what the URI carries and what an app takes by hand,
     * in groups of four for the eye.
     *
     * @param string|null $error a code the template translates
     */
    public function renderEnrolment(User $user, TotpProvisioning $provisioning, ?string $error = null, int $status = Response::HTTP_OK): Response
    {
        return $this->pages->render(
            'account/two_factor_enrol.html.twig',
            [
                'user' => $user,
                'qr_code' => $this->qrCode->svg($provisioning->uri),
                'key' => implode(' ', str_split(Base32::encodeUpperUnpadded($provisioning->secret->bytes), 4)),
                'error' => $error,
            ],
            $status,
        );
    }

    /**
     * @param list<string> $backupCodes in clear, this once
     */
    public function renderEnrolled(User $user, array $backupCodes): Response
    {
        return $this->pages->render('account/two_factor_enrolled.html.twig', [
            'user' => $user,
            'backup_codes' => $backupCodes,
        ]);
    }
}
