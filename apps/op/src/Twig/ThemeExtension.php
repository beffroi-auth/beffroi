<?php

declare(strict_types=1);

namespace App\Twig;

use App\Theme\ChosenTheme;
use App\Theme\Theme;
use Twig\Attribute\AsTwigFunction;

/**
 * What the layout reads to render the document in the theme it was asked for (issue #447).
 */
final readonly class ThemeExtension
{
    public function __construct(
        private ChosenTheme $chosen,
    ) {
    }

    #[AsTwigFunction(name: 'theme')]
    public function theme(): Theme
    {
        return $this->chosen->current();
    }
}
