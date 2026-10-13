<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class ProfileController extends AbstractController
{
    #[Route('/profile', name: 'app_profile')]
    public function __invoke(Security $security): Response
    {
        $token = $security->getToken();
        $idToken = $token?->hasAttribute('oidc_id_token') ? $token->getAttribute('oidc_id_token') : null;

        return $this->render('profile.html.twig', [
            'id_token_claims' => \is_string($idToken) ? self::payloadOf($idToken) : null,
        ]);
    }

    /**
     * The claims of an ID token the authenticator has already verified, decoded for display only.
     *
     * @return array<string, mixed>|null
     */
    private static function payloadOf(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (3 !== \count($parts)) {
            return null;
        }
        $json = base64_decode(strtr($parts[1], '-_', '+/'), true);
        $claims = false === $json ? null : json_decode($json, true);

        return \is_array($claims) ? $claims : null;
    }
}
