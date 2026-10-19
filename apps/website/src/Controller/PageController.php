<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The pages that only render a template: the teaser at the root, the thank-you page and the privacy notice.
 */
final class PageController extends AbstractController
{
    #[Route('/', name: 'app_home', methods: ['GET'])]
    public function home(): Response
    {
        return $this->render('home.html.twig');
    }

    #[Route('/symfonycon/thanks', name: 'app_signup_thanks', methods: ['GET'])]
    public function thanks(): Response
    {
        return $this->render('signup/thanks.html.twig');
    }

    #[Route('/privacy', name: 'app_privacy', methods: ['GET'])]
    public function privacy(): Response
    {
        return $this->render('privacy.html.twig');
    }
}
