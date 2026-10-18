<?php

declare(strict_types=1);

namespace App\Lead;

use Symfony\Contracts\Translation\TranslatableInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Where a lead stands, set by hand in the back office.
 */
enum LeadStatus: string implements TranslatableInterface
{
    case New = 'new';
    case Contacted = 'contacted';
    case Interested = 'interested';
    case NotInterested = 'not-interested';

    public function label(): string
    {
        return match ($this) {
            self::New => 'New',
            self::Contacted => 'Contacted',
            self::Interested => 'Interested',
            self::NotInterested => 'Not interested',
        };
    }

    public function trans(TranslatorInterface $translator, ?string $locale = null): string
    {
        return $this->label();
    }
}
