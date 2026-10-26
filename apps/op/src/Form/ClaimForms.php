<?php

declare(strict_types=1);

namespace App\Form;

use App\Controller\AccountProfileDescriptionController;
use Beffroi\Core\Domain\Identity\Claim\ClaimInterface;
use Beffroi\Core\Domain\Identity\User;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The form one claim of a person is offered as (issue beffroi-auth/op#17): the page that renders every
 * claim and the request that saves one both ask here, so what a browser was handed is what is read back
 * (issue beffroi-auth/beffroi#522).
 *
 * **Which is why the field is derived here and not by a caller.** What field a claim is offered as depends
 * on what is already held (beffroi-auth/beffroi#479), so a request that derived it otherwise than the page
 * that rendered it would read what was typed with another transformer: a birthdate held as a year alone is
 * a line of text on both sides, or it is a calendar on one and a line on the other.
 */
final readonly class ClaimForms
{
    public function __construct(
        private FormFactoryInterface $forms,
        private UrlGeneratorInterface $router,
    ) {
    }

    public function of(ClaimInterface $claim, User $user): FormInterface
    {
        $held = $claim->of($user);

        return $this->forms->create(ClaimType::class, [
            'value' => $held,
        ], [
            'claim' => $claim,
            'field' => $claim->field()->forHolding($held),
            'action' => $this->router->generate(AccountProfileDescriptionController::ROUTE, [
                'claim' => $claim->name(),
            ]),
        ]);
    }
}
