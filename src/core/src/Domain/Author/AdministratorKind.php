<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;

final readonly class AdministratorKind implements AuthorKindInterface
{
    public function kind(): string
    {
        return AnAdministrator::KIND;
    }

    public function fromDocument(Document $document): AuthorInterface
    {
        $subject =
            $document->nullableString(AnAdministrator::SUBJECT) ?? throw new InvalidArgumentException('An administrator who acted is named by the subject of their account.');

        return new AnAdministrator(new Subject($subject));
    }
}
