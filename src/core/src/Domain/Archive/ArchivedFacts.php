<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Archive;

use Beffroi\Core\Domain\Author\AuthorInterface;
use Beffroi\Core\Domain\Author\ToldByItsRoleInterface;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Session\RequestContext;
use DateTimeImmutable;
use DateTimeInterface;

final readonly class ArchivedFacts
{
    public static function moment(?DateTimeImmutable $moment): ?string
    {
        return $moment?->format(DateTimeInterface::ATOM);
    }

    /**
     * An act as the archive of the person it concerns holds it: one an author told by their role did says so, and nothing
     * else of them, neither who they are, nor the client they acted through, nor where they were.
     *
     * @return array<string, mixed>
     */
    public static function act(JournalEntry $act): array
    {
        if (! $act->author instanceof ToldByItsRoleInterface) {
            return self::actAsWritten($act);
        }

        return [
            'act' => $act->act,
            'occurred_at' => self::moment($act->occurredAt),
            'client' => null,
            'from' => null,
            'author' => self::author($act->author),
        ];
    }

    /**
     * An act as the journal holds it, its author by what names them among their kind: what the operator of the instance
     * reads. An act written before acts named the kind of their author names none.
     *
     * @return array<string, mixed>
     */
    public static function actAsWritten(JournalEntry $act): array
    {
        return [
            'act' => $act->act,
            'occurred_at' => self::moment($act->occurredAt),
            'client' => $act->client,
            'from' => self::context($act->context),
            'author' => $act->author?->toDocument(),
        ];
    }

    /**
     * What the person is told of who acted on them: an author told by their role by their kind alone, any other by the
     * document it writes (decision 0066).
     *
     * @return non-empty-array<string, string>
     */
    public static function author(AuthorInterface $author): array
    {
        return $author instanceof ToldByItsRoleInterface ? [AuthorInterface::MEMBER => $author->kind()] : $author->toDocument();
    }

    /**
     * Base64url: raw octets handed to the JSON encoder would leave a person with no document.
     */
    public static function octets(?string $octets): ?string
    {
        return $octets === null ? null : Base64Url::encode($octets);
    }

    /**
     * @return array<string, mixed>
     */
    public static function context(RequestContext $context): array
    {
        return [
            'received_at' => self::moment($context->receivedAt),
            'ip_address' => $context->ipAddress,
            'user_agent' => $context->userAgent,
            'location' => $context->location === null
                ? null
                : [
                    'country_code' => $context->location->countryCode,
                    'region' => $context->location->region,
                    'city' => $context->location->city,
                    'autonomous_system_number' => $context->location->autonomousSystemNumber,
                    'autonomous_system_organization' => $context->location->autonomousSystemOrganization,
                    'latitude' => $context->location->latitude,
                    'longitude' => $context->location->longitude,
                ],
            'device' => $context->device === null
                ? null
                : [
                    'type' => $context->device->type->value,
                    'browser' => $context->device->browser,
                    'browser_version' => $context->device->browserVersion,
                    'platform' => $context->device->platform,
                    'platform_version' => $context->device->platformVersion,
                ],
        ];
    }
}
