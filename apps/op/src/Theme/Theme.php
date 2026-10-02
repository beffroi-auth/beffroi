<?php

declare(strict_types=1);

namespace App\Theme;

/**
 * What the pages are rendered in (issue #447): the two themes the stylesheet declares, and the third
 * choice, which is to let the browser answer. DaisyUI is configured with "light --default" and
 * "dark --prefersdark" (assets/styles/app.css), so a document that names no theme follows
 * prefers-color-scheme on its own: System is the absence of the attribute and not a theme beside the two.
 *
 * An enum and not a class per case: nothing behaves per theme. The value is carried to the document and
 * read by a stylesheet.
 */
enum Theme: string
{
    case Light = 'light';
    case Dark = 'dark';
    case System = 'system';

    /**
     * What was asked for, and the choice that leaves it to the browser when what was asked for is not a
     * theme this deployment has.
     */
    public static function ofChoice(?string $choice): self
    {
        return self::tryFrom($choice ?? '') ?? self::System;
    }

    /**
     * The value of the "data-theme" attribute of the document, null when the browser decides.
     */
    public function attribute(): ?string
    {
        return $this === self::System ? null : $this->value;
    }
}
