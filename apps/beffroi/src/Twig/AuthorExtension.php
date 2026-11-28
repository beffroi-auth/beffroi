<?php

declare(strict_types=1);

namespace App\Twig;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ToldByItsNameInterface;
use Beffroi\Core\Domain\Author\ToldByItsRoleInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use Twig\Attribute\AsTwigFilter;

/**
 * Who did an act, as the person it concerns reads it (decision 0066): an author told by their name by the string of
 * their kind that names them (`author.<kind>.named`), one told by their role by the string of their kind
 * (`author.<kind>`), and nothing for one the page tells by where the act came from.
 */
final readonly class AuthorExtension
{
    public function __construct(
        private TranslatorInterface $translator,
    ) {
    }

    #[AsTwigFilter(name: 'beffroi_author')]
    public function told(?AuthorInterface $author): ?string
    {
        if ($author instanceof ToldByItsNameInterface) {
            return $this->translator->trans('author.' . $author->kind() . '.named', ['name' => $author->name()], 'beffroi');
        }
        if ($author instanceof ToldByItsRoleInterface) {
            return $this->translator->trans('author.' . $author->kind(), [], 'beffroi');
        }

        return null;
    }
}
