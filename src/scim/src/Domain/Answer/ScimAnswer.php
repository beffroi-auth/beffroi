<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Answer;

use Beffroi\Scim\Domain\Error\ScimError;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use JsonException;

/**
 * Section 5.1, RFC 7644 §8.1: what the module answers, a SCIM document that no cache between the provider and the
 * directory keeps (RFC 9111 §5.2.2.5), since what it carries is the tenant and its people.
 */
final readonly class ScimAnswer
{
    public const string MEDIA_TYPE = 'application/scim+json';

    /**
     * @param array<string, mixed> $document
     * @param array<string, string> $headers what the answer carries beside its type and its cache directive, which it
     *                                       never replaces
     */
    public function __construct(
        public int $status,
        public array $document,
        private array $headers = [],
    ) {
    }

    /**
     * @param array<string, string> $headers
     */
    public static function error(ScimError $error, array $headers = []): self
    {
        return new self($error->status, $error->toDocument(), $headers);
    }

    /**
     * @return array<string, string>
     */
    public function headers(): array
    {
        return (
            [
                'Content-Type' => self::MEDIA_TYPE,
                'Cache-Control' => 'no-store',
            ] + $this->headers
        );
    }

    /**
     * @throws JsonException
     */
    public function body(): string
    {
        return json_encode($this->document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
