<?php

declare(strict_types=1);

namespace App\Controller;

use App\Theme\ChosenTheme;
use App\Theme\Theme;
use function preg_match;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The theme a visitor asked for, kept for their browser (issue #447): a route of this application and
 * not of the bundle, the look of the pages being the decision of whoever installs it (architecture §5.2).
 *
 * It answers a form and no script: the choice is a POST that comes back to the page it was made on, so
 * the pages work for a browser that runs nothing, and a theme is never a path (architecture §5.7, the
 * rule the language of the pages already follows).
 */
#[AsController]
final readonly class ChooseThemeController
{
    public const string ROUTE = 'app_theme';

    public function __construct(
        private ChosenTheme $chosen,
    ) {
    }

    #[Route('/theme', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $response = new RedirectResponse(self::backTo($request));
        $response->headers->setCookie($this->chosen->cookie(Theme::ofChoice($request->request->getString('theme'))));

        return $response;
    }

    /**
     * The page the choice was made on, which the form carries, and the root of the application for
     * anything that is not a path of this origin: a choice of colour does not send a browser elsewhere.
     */
    private static function backTo(Request $request): string
    {
        $target = $request->request->getString('target');

        return preg_match('#^/(?![/\\\\])[^\s\\\\]*$#', $target) === 1 ? $target : '/';
    }
}
