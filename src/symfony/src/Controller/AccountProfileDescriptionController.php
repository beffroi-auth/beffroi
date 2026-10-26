<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\ProfilePage;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Identity\WiredClaims;
use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A person says something of themselves (issue #452, architecture §5.2). What the tenant does not open is
 * refused here and not merely left off the page: a page that only hides a field it must not offer is a
 * page whose form can be sent anyway, so the rule is the use case's and this asks it (SelfDescription).
 *
 * A claim this provider does not hold at all is not a refusal but nothing: there is no such field, as
 * there is no such page for an application somebody agreed to nothing for.
 *
 * It answers with a redirection whether the use case accepted or refused (issue #481), so that a browser
 * reloading the page does not say the same thing of that person again.
 */
#[AsController]
final readonly class AccountProfileDescriptionController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_profile_describe';

    public const string CSRF_TOKEN_ID = 'beffroi_profile_describe';

    public const string CLAIM_PARAMETER = 'claim';

    public const string VALUE_PARAMETER = 'value';

    public function __construct(
        private AccountAccess $account,
        private WiredClaims $claims,
        private SelfDescription $description,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/profile', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $parameters = RequestParameters::ofBrowserRequest($request);
        $named = $parameters[self::CLAIM_PARAMETER] ?? null;
        $claim = is_string($named) ? $this->claims->named($named) : null;
        if ($claim === null) {
            throw new NotFoundHttpException('No such claim.');
        }
        $value = $parameters[self::VALUE_PARAMETER] ?? null;
        $said = is_string($value) && $value !== '' ? $value : null;
        try {
            $this->description->describe($session->user, $claim, $said, $this->contexts->fromRequest($request));
        } catch (InvalidArgumentException) {
            // the claim is not this person's to change, the tenant not opening it or the source that
            // created them holding it, or the value is not one the claim holds; which of the two is what
            // the page says, and neither is a reason to say more than that. It crosses the redirection in
            // the session and never the value that was refused (issue #481).
            $this->refusals->keep(
                $request,
                $session->user->maySayOfThemselves($claim->name()) ? ProfilePage::REFUSED : ProfilePage::NOT_OPEN,
                $claim->name(),
            );
        }

        return $this->pages->afterTheForm(AccountProfileController::ROUTE);
    }
}
