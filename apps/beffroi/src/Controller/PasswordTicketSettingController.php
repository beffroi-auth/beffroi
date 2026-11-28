<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\FormToken;
use App\Http\InteractionPages;
use App\Http\PresentedTicket;
use App\Http\RequestContextFactory;
use App\Http\WhatWasRefused;
use Beffroi\Core\Application\Ticket\PasswordTicketRedemption;
use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Beffroi\Core\Exception\PasswordRefusedException;
use Beffroi\Core\Exception\TicketRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The password a person poses with a ticket, typed twice (decision 0026): the ticket is spent once it is written, and
 * every session of the person ends with it. The browser then goes to the account, which offers the login.
 */
#[AsController]
final readonly class PasswordTicketSettingController
{
    public const string ROUTE = 'beffroi_interaction_password_ticket_set';

    public const string CSRF_TOKEN_ID = 'beffroi_password_ticket';

    /**
     * The floor of the tenant or the domain of the person admits no password, which a ticket issued before either
     * changed may still name.
     */
    public const string NOT_ADMITTED = 'not_admitted';

    public function __construct(
        private PresentedTicket $tickets,
        private PasswordTicketRedemption $redemption,
        private FormToken $formTokens,
        private WhatWasRefused $refusals,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
    ) {
    }

    #[Route(
        '/password/{ticket}/{value}',
        name: self::ROUTE,
        requirements: [
            'ticket' => '[0-9a-fA-F-]{36}',
        ],
        methods: ['POST'],
    )]
    public function __invoke(Request $request): Response
    {
        $ticket = $this->tickets->of($request, $this->redemption->redeem(...));
        if ($ticket === null) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, PasswordTicketController::REFUSED);
        }
        $refusal = $this->formTokens->refusal($request->request->getString(FormToken::PARAMETER), self::CSRF_TOKEN_ID);
        if ($refusal !== null) {
            return $refusal;
        }
        try {
            $posed = new PlainPassword(
                $request->request->getString(AccountPasswordChangeController::POSED_PARAMETER),
                PasswordLength::under($ticket->tenant->loginFloor),
            );
        } catch (PasswordRefusedException $exception) {
            return $this->refused($request, $exception->refusal->value);
        }
        if (! $posed->confirmedBy($request->request->getString(AccountPasswordChangeController::POSED_AGAIN_PARAMETER))) {
            return $this->refused($request, AccountPasswordChangeController::NOT_CONFIRMED);
        }
        try {
            $this->redemption->spend(
                $ticket,
                $posed,
                $this->contexts->fromRequest($request),
            );
        } catch (PasswordRefusedException|PasswordChangeRefusedException $exception) {
            return $this->refused($request, $exception->refusal->value);
        } catch (CredentialEnrolmentFailedException) {
            return $this->refused($request, self::NOT_ADMITTED);
        } catch (TicketRefusedException) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, PasswordTicketController::REFUSED);
        }

        return $this->pages->afterTheForm(AccountController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(PasswordTicketController::ROUTE, $this->tickets->parameters($request));
    }
}
