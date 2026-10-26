<?php

declare(strict_types=1);

namespace App\Controller;

use App\Form\ClaimForms;
use Beffroi\Bundle\Controller\AccountProfileDescriptionController as BundleProfileForm;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\ProfilePage;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Identity\WiredClaims;
use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Domain\Identity\Claim\ClaimInterface;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_string;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;

/**
 * A person says one thing of themselves on the page of this application (issue beffroi-auth/op#17), the
 * claim being the one named in the URL: one form per claim, so nothing is read back out of a body to know
 * which was submitted.
 *
 * **It answers with a redirection whether the use case accepted or refused** (issue
 * beffroi-auth/beffroi#481), so that a browser reloading the page it comes back to does not say the same
 * thing of that person again. What was refused crosses that redirection in the session (WhatWasRefused),
 * and the page puts it back under the field it is about, which is what this application installs a form
 * component for.
 *
 * The rule of what a person may change is not here: the use case of the core reads it, on the server, for
 * every caller (SelfDescription). What this reads of it is which claims the page has a field for, and a
 * name it has none for is answered with nothing at all.
 */
#[AsController]
final readonly class AccountProfileDescriptionController
{
    /**
     * The route name of the form of the bundle, which this answers in its place, so that every link naming
     * it lands here (config/routes/profile.yaml).
     */
    public const string ROUTE = BundleProfileForm::ROUTE;

    public function __construct(
        private AccountAccess $account,
        private WiredClaims $claims,
        private ClaimForms $claimForms,
        private SelfDescription $description,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/profile/{claim}', name: self::ROUTE, methods: ['POST'], requirements: [
        'claim' => '[a-z_]+',
    ])]
    public function __invoke(Request $request, string $claim): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        $named = $this->claims->named($claim);
        if ($named === null || ! $user->tenant->selfServedClaims->opens($named->name())) {
            // this page offers a field per claim the tenant opens, so a name it offers none for is not a
            // refusal of the page but a URL that is not one of its own, and there is no page to be
            // redirected to about it; what writes still reads the policy itself (SelfDescription)
            throw new NotFoundHttpException('No such claim.');
        }
        $form = $this->claimForms->of($named, $user);
        $form->handleRequest($request);
        // a body that carries nothing of this form was never submitted, and carries no token either
        if (! $form->isSubmitted() || self::theTokenDidNotHold($form)) {
            return $this->pages->error(Response::HTTP_FORBIDDEN, InteractionPages::INVALID_CSRF_TOKEN);
        }
        $refusal = $this->describe($request, $form, $named, $user);
        if ($refusal !== null) {
            $this->refusals->keep($request, $refusal, $named->name());
        }

        return $this->pages->afterTheForm(AccountProfileController::ROUTE);
    }

    /**
     * What this provider refuses of what was said, a code the page translates, and null once it is written.
     *
     * Two things refuse and the page says the same of both, because what a person reads under the line is
     * that what they typed is not a value for it either way: the component refuses what it cannot read as
     * the kind of field the claim is offered as, a birthdate that is not a date for one, and the claim
     * refuses what it does not hold, a name the zoneinfo database does not carry for another. What the use
     * case refuses for want of the tenant opening the claim does not arrive here, the page having answered
     * nothing at all for a claim it offers no field for.
     *
     * Never the value that was refused: a refusal crosses a redirection in the session of the browser, and
     * a session is a disk (issue beffroi-auth/beffroi#481).
     */
    private function describe(Request $request, FormInterface $form, ClaimInterface $claim, User $user): ?string
    {
        if (! $form->isValid()) {
            return ProfilePage::REFUSED;
        }
        $said = $form->get('value')->getData();
        try {
            $this->description->describe($user, $claim, is_string($said) && $said !== '' ? $said : null, $this->contexts->fromRequest($request));
        } catch (InvalidArgumentException) {
            return ProfilePage::REFUSED;
        }

        return null;
    }

    /**
     * Whether what came back did not carry the token of the page it was rendered on, which is the one
     * refusal of this form that keeps its error page instead of crossing a redirection (issue
     * beffroi-auth/beffroi#481): a request without a token carries no state, so a browser repeating it gets
     * the same answer and there is nothing for a page after a redirection to show.
     *
     * The component checks the token itself (config/packages/csrf.yaml) and says so on the form rather
     * than under the field, with the token it refused as the cause of the error; that is what this reads,
     * so a value the field refused is never taken for a token that did not hold.
     */
    private static function theTokenDidNotHold(FormInterface $form): bool
    {
        foreach ($form->getErrors() as $error) {
            if ($error->getCause() instanceof CsrfToken) {
                return true;
            }
        }

        return false;
    }
}
