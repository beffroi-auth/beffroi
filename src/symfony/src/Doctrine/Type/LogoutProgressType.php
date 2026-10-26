<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;

/**
 * Where a chain of SAML logout stands (beffroi/saml, spec/saml.md S-32) as a JSON column. What the document holds is
 * the progress's own (`LogoutProgress::toDocument()`).
 *
 * @extends JsonObjectType<LogoutProgress>
 */
final class LogoutProgressType extends JsonObjectType
{
    public const string NAME = 'beffroi_saml_logout_progress';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return LogoutProgress::fromDocument($data);
    }

    protected function expects(): string
    {
        return LogoutProgress::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
