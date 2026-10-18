<?php

declare(strict_types=1);

namespace App\Lead;

use Symfony\Contracts\Translation\TranslatableInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The answer to "which OpenID Connect provider do you use today?", in the order the form lists them.
 */
enum OidcProvider: string implements TranslatableInterface
{
    case Keycloak = 'keycloak';
    case Auth0 = 'auth0';
    case Okta = 'okta';
    case EntraId = 'entra-id';
    case Cognito = 'cognito';
    case Google = 'google';
    case Authentik = 'authentik';
    case Zitadel = 'zitadel';
    case Ory = 'ory';
    case FusionAuth = 'fusionauth';
    case InHouse = 'in-house';
    case Other = 'other';
    case None = 'none';

    public function label(): string
    {
        return match ($this) {
            self::Keycloak => 'Keycloak',
            self::Auth0 => 'Auth0',
            self::Okta => 'Okta',
            self::EntraId => 'Microsoft Entra ID',
            self::Cognito => 'AWS Cognito',
            self::Google => 'Google (Firebase, Identity Platform)',
            self::Authentik => 'Authentik',
            self::Zitadel => 'Zitadel',
            self::Ory => 'Ory',
            self::FusionAuth => 'FusionAuth',
            self::InHouse => 'Built in-house',
            self::Other => 'Other',
            self::None => 'None',
        };
    }

    public function trans(TranslatorInterface $translator, ?string $locale = null): string
    {
        return $this->label();
    }
}
