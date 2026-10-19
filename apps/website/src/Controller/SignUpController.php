<?php

declare(strict_types=1);

namespace App\Controller;

use App\Lead\LeadRequest;
use App\Lead\LeadType;
use App\Lead\Registration;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The landing page of SymfonyCon Warsaw 2026 and its sign-up form. A valid sign-up redirects to the thank-you page,
 * an invalid one shows the form again with its errors (422).
 */
final class SignUpController extends AbstractController
{
    public const string SOURCE = 'symfonycon-warsaw-2026';

    public function __construct(private readonly Registration $registration)
    {
    }

    #[Route('/symfonycon', name: 'app_signup', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $form = $this->createForm(LeadType::class, new LeadRequest());
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $this->registration->register($form->getData(), self::SOURCE);

            return $this->redirectToRoute('app_signup_thanks', status: Response::HTTP_SEE_OTHER);
        }

        return $this->render('signup/index.html.twig', ['form' => $form]);
    }
}
