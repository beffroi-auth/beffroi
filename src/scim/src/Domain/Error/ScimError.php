<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Error;

/**
 * RFC 7644 §3.12: the status, as a JSON string, the keyword of Table 9 where it has one, and a detail written from the
 * rule refused and never from what the request carried (P-19).
 */
final readonly class ScimError
{
    public const string SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

    public function __construct(
        public int $status,
        public ?ScimType $scimType,
        public string $detail,
    ) {
    }

    /**
     * @return array{schemas: list<string>, status: string, scimType?: string, detail: string}
     */
    public function toDocument(): array
    {
        $document = [
            'schemas' => [self::SCHEMA],
            'status' => (string) $this->status,
        ];
        if ($this->scimType instanceof ScimType) {
            $document['scimType'] = $this->scimType->value;
        }
        $document['detail'] = $this->detail;

        return $document;
    }
}
