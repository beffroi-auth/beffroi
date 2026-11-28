<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Author;

use Beffroi\Core\Domain\Encoding\PlainText;
use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * An identity provider the tenant federates with, SAML or OpenID Connect, by the name the deployment declares it under:
 * the author of what a sign-in through it writes (decision 0066).
 */
final readonly class AnUpstreamProvider implements ToldByItsNameInterface
{
    public const string KIND = 'upstream';

    public const string NAME = 'name';

    /**
     * @throws InvalidArgumentException when the name is blank or not plain text
     */
    public function __construct(
        public string $name,
    ) {
        if (PlainText::isBlank($name) || ! PlainText::holds($name, PlainText::MAX_LENGTH)) {
            throw new InvalidArgumentException('An upstream provider is named by the name the deployment declares it under, plain text and never blank.');
        }
    }

    public function kind(): string
    {
        return self::KIND;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function toDocument(): array
    {
        return [self::MEMBER => self::KIND, self::NAME => $this->name];
    }
}
