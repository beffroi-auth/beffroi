<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Identity\Subject;

/**
 * An administrator of the tenant, acting through the administration API (decision 0038), named by the subject of their
 * account, which says nothing about them.
 */
final readonly class AnAdministrator implements ToldByItsRoleInterface
{
    public const string KIND = 'administrator';

    public const string SUBJECT = 'subject';

    public function __construct(
        public Subject $subject,
    ) {
    }

    public function kind(): string
    {
        return self::KIND;
    }

    public function toDocument(): array
    {
        return [self::MEMBER => self::KIND, self::SUBJECT => $this->subject->value];
    }
}
