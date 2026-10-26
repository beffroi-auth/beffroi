<?php

declare(strict_types=1);

namespace App\Controller;

use App\Form\ClaimForms;
use Beffroi\Bundle\Controller\AccountProfileController as BundleProfilePage;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Http\Account\RecordedInformation;
use Beffroi\Bundle\Identity\WiredClaims;
use function count;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * What this provider holds of the signed-in person, and what they may correct of it, edited in place
 * (issue beffroi-auth/op#17).
 *
 * **This page is the application's and not the bundle's**, which is why it answers the route name of the
 * bundle rather than adding one of its own: a deployment that installs the bundle is served bare HTML with
 * a form token, and this one, which is the reference deployment, shows what the same thing looks like
 * written with symfony/form. The rule of what a person may change is not here either way: it is read by
 * the use case of the core (SelfDescription), on the server, for every caller.
 *
 * One form per claim, because what this page does is let somebody correct one thing where they read it,
 * and a single form would make them save thirteen others to do it. Which form was submitted is the claim
 * named in the URL of what it posts to (AccountProfileDescriptionController), so nothing is read back out
 * of a body to know which.
 *
 * It renders no script. The value a person reads is the field they type into, which is a stylesheet and
 * not a behaviour (assets/styles/app.css).
 *
 * What they have changed of their record is a page of its own (issue beffroi-auth/beffroi#482), served by
 * the bundle: this page offers the way to it and reads none of it.
 */
#[AsController]
final readonly class AccountProfileController
{
    /**
     * The route name of the page of the bundle, which this page answers in its place, so that every link
     * naming it lands here (config/routes/profile.yaml).
     */
    public const string ROUTE = BundleProfilePage::ROUTE;

    public function __construct(
        private AccountAccess $account,
        private WiredClaims $claims,
        private ClaimForms $claimForms,
        private WhatWasRefused $refusals,
        private TranslatorInterface $translator,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/profile', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        // what a form of this page was refused, if one was, shown this once: it crossed the redirection
        // the form answered with and the page it was read by has taken it (issue beffroi-auth/beffroi#481)
        $refusal = $this->refusals->take($request);
        $forms = [];
        foreach ($this->claims->openedTo($user) as $open) {
            $form = $this->claimForms->of($open, $user);
            if ($refusal?->field === $open->name()) {
                // the message goes back under the line it is about, which is what this page has a form
                // component for; what crossed is the code, and the sentence is a word of the catalogue of
                // the bundle and never the sentence of an exception, which is written for whoever reads logs
                $form->get('value')->addError(new FormError($this->translator->trans('profile.' . $refusal->code, [], 'beffroi')));
            }
            $forms[$open->name()] = $form->createView();
        }

        return $this->pages->render('account/profile.html.twig', [
            'user' => $user,
            'identity' => RecordedInformation::identityOf($user),
            // every claim this provider can hold, so that the line somebody reads is the line they
            // correct; how many of them are held is what the page says of the record itself
            'claims' => RecordedInformation::everyClaimOf($user),
            'held' => count(RecordedInformation::claimsOf($user)),
            // one view per claim the tenant opens and the source of the person does not hold, in the order
            // the claims are wired, each built once
            // what was refused of it is on its field
            'forms' => $forms,
        ]);
    }
}
