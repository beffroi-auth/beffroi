<?php

declare(strict_types=1);

namespace App\Fido\Conformance;

use App\Doctrine\TenantProvider;
use Beffroi\Core\Application\Passkey\PasskeyEnrolment;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use InvalidArgumentException;
use Beffroi\Core\Exception\UsernameUniquenessPendingException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialCreationOptions;

/**
 * FIDO2 server API, ServerPublicKeyCredentialCreationOptionsRequest
 */
#[AsController]
final readonly class AttestationOptionsController
{
    public const string ROUTE = 'beffroi_fido_conformance_attestation_options';

    public function __construct(
        private TenantProvider $tenants,
        private ConformanceUsers $users,
        private PasskeyEnrolment $enrolment,
        private WebauthnCeremonies $ceremonies,
        private CeremonyStore $store,
    ) {
    }

    #[Route('/attestation/options', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $body = ServerRequest::fromRequest($request);
            $user = $this->users->findOrCreate($this->tenants->provide(), $body->string('username'), $body->string('displayName'));
            $options = self::options($this->enrolment->begin($user), $body);
        } catch (InvalidArgumentException|InvalidDataException|UsernameUniquenessPendingException $exception) {
            return ServerResponse::failed($exception->getMessage());
        }
        $this->store->storeCreation($user->id, $options);

        return ServerResponse::options($this->ceremonies->optionsToJson($options));
    }

    /**
     * @throws ServerRequestException
     * @throws InvalidArgumentException
     * @throws InvalidDataException
     */
    private static function options(PublicKeyCredentialCreationOptions $drawn, ServerRequest $body): PublicKeyCredentialCreationOptions
    {
        $selection = $body->optionalObject('authenticatorSelection');
        $residentKey = $selection?->optionalString('residentKey');
        if ($residentKey === null && $selection?->optionalBool('requireResidentKey') === true) {
            $residentKey = AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED;
        }
        $extensions = [];
        foreach ($body->optionalObject('extensions')?->members() ?? [] as $name => $value) {
            $extensions[] = AuthenticationExtension::create($name, $value);
        }

        return PublicKeyCredentialCreationOptions::create(
            $drawn->rp,
            $drawn->user,
            $drawn->challenge,
            $drawn->pubKeyCredParams,
            AuthenticatorSelectionCriteria::create(
                $selection?->optionalString('authenticatorAttachment'),
                $selection?->optionalString('userVerification') ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                $residentKey,
            ),
            $body->optionalString('attestation') ?? PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $drawn->excludeCredentials,
            CeremonyStore::LIFETIME * 1000,
            AuthenticationExtensions::create($extensions),
        );
    }
}
