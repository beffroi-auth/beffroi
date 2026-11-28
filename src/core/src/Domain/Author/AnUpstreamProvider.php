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
     * In characters: the entity ID of a SAML identity provider, the longest name a deployment declares one under
     * (SAML Metadata §2.2.1).
     */
    public const int MAX_LENGTH = 1024;

    /**
     * @throws InvalidArgumentException when the name is blank, not plain text or longer than an author holds
     */
    public function __construct(
        public string $name,
    ) {
        if (! self::holds($name)) {
            throw new InvalidArgumentException('An upstream provider is named by the name the deployment declares it under, plain text, never blank and at most 1024 characters.');
        }
    }

    /**
     * The rule a declaration holds the name of an upstream provider to, so that what a sign-in through it writes names
     * it.
     */
    public static function holds(string $name): bool
    {
        return ! PlainText::isBlank($name) && PlainText::holds($name, self::MAX_LENGTH);
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
