<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;

/**
 * Logout requests accepted from the service provider whose metadata the model's writer signs with the test key of a
 * service provider (ServiceProviderDocuments::SIGNED), answered over HTTP-Redirect at its single logout service; a test
 * names what it changes.
 */
final readonly class SignOutRequests
{
    public const string ID = '_9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b';

    public const string SINGLE_LOGOUT = ServiceProviderDocuments::SIGNED . '/slo';

    public const string REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    public const string POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /**
     * @param list<string> $sessionIndexes
     */
    public static function request(
        string $nameId,
        array $sessionIndexes,
        string $nameIdFormat = PersistentNameId::FORMAT,
        ?string $nameQualifier = null,
        ?string $spNameQualifier = null,
        ?string $relayState = 'state-1',
        string $answerBinding = self::REDIRECT,
        string $answerLocation = self::SINGLE_LOGOUT,
    ): SignOutRequest {
        return new SignOutRequest(
            ServiceProviderDocuments::SIGNED,
            self::ID,
            $nameId,
            $nameIdFormat,
            $nameQualifier,
            $spNameQualifier,
            $sessionIndexes,
            $relayState,
            $answerBinding,
            $answerLocation,
        );
    }
}
