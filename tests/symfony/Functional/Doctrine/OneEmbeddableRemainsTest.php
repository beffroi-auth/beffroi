<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use function array_diff;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Doctrine\DBAL\Types\Type;
use function method_exists;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use ReflectionNamedType;
use ReflectionProperty;
use function sort;
use function str_starts_with;

/**
 * Decision 0027 and the SOLID rule of `AGENTS.md`: a value object a column holds whole writes its own
 * document, and **no mapping of the bundle holds a Doctrine embeddable** but one. That one is the
 * authorization request an interaction parks (architecture §5.3), and what keeps it is not a preference.
 *
 * **Its first field is a `Client`**, which the mapping carries no entity for: a registration is read back
 * from wherever registrations are read, at every load (`ClientResolver`, `ResolvesItsClientInterface`). A
 * DBAL type is asked for a complete object and the constructor of a request requires that client, so no
 * type can hand this object back whole. Its seventeen other fields are value objects that already have a
 * type each, and a single column would have to absorb eight of them.
 *
 * **Why a test rather than the comment the mapping already carries.** A second embeddable costs nothing
 * to add and no rule of the mapping refuses it, and the figures the exemption rests on are read nowhere:
 * the day the client of a request stops being resolved after the load, or the day those eight types
 * become one, the reason is gone and the embeddable has to go with it. What the walk of the schema
 * already holds is the other half, the sealing: the two hints of a request are sealed under the family of
 * the one table that carries them, and a second entity embedding this object would seal them under a
 * scope that is not its own (`SchemaClassificationTest`, `ClassifiedSchema`).
 */
final class OneEmbeddableRemainsTest extends DatabaseTestCase
{
    /**
     * The fields of the request the mapping carries, which is every field of it but the client.
     */
    private const int FIELDS = 17;

    /**
     * How many types of the bundle a single column holding this object whole would have to absorb, which
     * is the count of distinct types over those seventeen fields: the two hints share one.
     */
    private const int TYPES = 8;

    /**
     * How many of those eight are handed a registry when the bundle boots, Doctrine building a type from a
     * class name with nothing to give it: the PKCE methods a stored challenge names its own with, and the
     * detail types an `authorization_details` is read back as. A type that needs the wiring takes it
     * through the `resolveWith()` of its capability (`NeedsCodeChallengeMethodsInterface`,
     * `NeedsAuthorizationDetailTypesInterface`), which is what names them here.
     */
    private const int TYPES_THAT_READ_A_REGISTRY = 2;

    /**
     * The classes of the packages, which are the mappings of the bundle: what a host application embeds in
     * its own entities is not the bundle's to refuse (decision 0002).
     */
    private const string PACKAGES = 'Beffroi\\';

    /**
     * The prefix of a type of the bundle, a field carrying a type of Doctrine being a field a single
     * column would absorb nothing of.
     */
    private const string TYPE_PREFIX = 'beffroi_';

    #[Test]
    public function theMappingsOfTheBundleEmbedOneObject(): void
    {
        // When / Then
        static::assertSame([AuthorizationRequest::class], array_keys(self::embeddedObjects()));
    }

    /**
     * One entity embeds it, which is what makes the type of its two sealed fields right: a field of an
     * embeddable carries the family of a table only while a single entity embeds the object.
     */
    #[Test]
    public function oneEntityEmbedsThatObject(): void
    {
        // When / Then
        static::assertSame([Interaction::class], self::embeddedObjects()[AuthorizationRequest::class]);
    }

    /**
     * The reason the exemption rests on: the one property of the request no field of the mapping carries
     * is its client, and the class it is typed as is no entity of the mapping, so nothing is joined to it
     * and no type reads it back.
     */
    #[Test]
    public function theClientOfARequestIsTheOnePropertyNoFieldCarries(): void
    {
        // Given
        $properties = array_map(
            static fn (ReflectionProperty $property): string => $property->getName(),
            new ReflectionClass(AuthorizationRequest::class)->getProperties(),
        );
        $type = new ReflectionProperty(AuthorizationRequest::class, 'client')->getType();

        // When
        $carriedByNoField = array_values(array_diff($properties, array_keys(self::fields())));

        // Then
        static::assertSame(['client'], $carriedByNoField);
        static::assertSame(Client::class, $type instanceof ReflectionNamedType ? $type->getName() : null);
        static::assertArrayNotHasKey(Client::class, self::mappedClasses());
    }

    /**
     * And the entity that embeds it is the one that declares the request as where its client is held
     * (`ResolvesItsClientInterface`): the day an interaction carries its own, the embeddable has nothing
     * left a type could not do.
     */
    #[Test]
    public function theEntityThatEmbedsItHoldsItsClientOnIt(): void
    {
        // Given
        $client = self::client();
        $request = new AuthorizationRequest($client, $client->registration->redirectUris[0], new Scopes([new Scope('openid')]), null);
        $interaction = new Interaction(Secrets::draw(), self::tenant(), $request, null, self::now(), self::now()->modify('+10 minutes'));

        // When / Then
        static::assertSame($request, $interaction->clientHolder());
    }

    /**
     * Where the seventeen columns of the exemption are: on the table of the entity that embeds the object,
     * under no prefix, and on no other table.
     */
    #[Test]
    public function theSeventeenFieldsOfTheRequestAreColumnsOfTheInteraction(): void
    {
        // When / Then
        static::assertCount(self::FIELDS, self::fields());
        static::assertSame('beffroi_interaction', self::entityManager()->getClassMetadata(Interaction::class)->getTableName());
    }

    /**
     * What a ninth type would have to absorb: eight types of the bundle over those seventeen fields, each
     * one the type of a value object that writes its own document (decision 0027).
     */
    #[Test]
    public function aSingleColumnWouldHaveToAbsorbEightTypesOfTheBundle(): void
    {
        // When / Then
        static::assertCount(self::TYPES, self::typesOfTheBundle());
    }

    /**
     * Two of those eight are handed a registry, which a type reading one document for the whole object
     * would have to be handed too, and which is what the SOLID rule of `AGENTS.md` refuses to gather in
     * one class.
     */
    #[Test]
    public function twoOfThoseTypesAreHandedARegistryAtBoot(): void
    {
        // Given
        $handed = [];
        foreach (self::typesOfTheBundle() as $name) {
            if (method_exists(Type::getType($name), 'resolveWith')) {
                $handed[] = $name;
            }
        }

        // When / Then
        static::assertCount(self::TYPES_THAT_READ_A_REGISTRY, $handed);
    }

    /**
     * The objects the mappings of the bundle embed, by the entities that embed each one: an embeddable is
     * read from the entities, which is where its columns land, and the metadata of an embeddable itself is
     * skipped so that an object nested in one is named after the entity that carries it.
     *
     * @return array<class-string, list<class-string>>
     */
    private static function embeddedObjects(): array
    {
        $embedded = [];
        foreach (self::entityManager()->getMetadataFactory()->getAllMetadata() as $metadata) {
            if ($metadata->isEmbeddedClass || $metadata->isMappedSuperclass || ! str_starts_with($metadata->getName(), self::PACKAGES)) {
                continue;
            }
            foreach ($metadata->embeddedClasses as $mapping) {
                $embedded[$mapping->class][] = $metadata->getName();
            }
        }

        return $embedded;
    }

    /**
     * The fields of the request the mapping carries, by the column each one lands in, read from the entity
     * that embeds it, which is what says the column is on that entity's table.
     *
     * @return array<string, string>
     */
    private static function fields(): array
    {
        $metadata = self::entityManager()->getClassMetadata(Interaction::class);
        $fields = [];
        foreach ($metadata->fieldMappings as $field => $mapping) {
            if ($mapping->originalClass !== AuthorizationRequest::class) {
                continue;
            }
            $fields[$mapping->originalField ?? $field] = $metadata->getColumnName($field);
        }

        return $fields;
    }

    /**
     * The distinct types of the bundle over the fields of the request.
     *
     * @return list<string>
     */
    private static function typesOfTheBundle(): array
    {
        $types = [];
        foreach (self::entityManager()->getClassMetadata(Interaction::class)->fieldMappings as $mapping) {
            if ($mapping->originalClass !== AuthorizationRequest::class || ! str_starts_with($mapping->type, self::TYPE_PREFIX)) {
                continue;
            }
            $types[] = $mapping->type;
        }
        $types = array_values(array_unique($types));
        sort($types);

        return $types;
    }

    /**
     * Every class the mappings describe, which is what says a class is not one of them.
     *
     * @return array<class-string, true>
     */
    private static function mappedClasses(): array
    {
        $classes = [];
        foreach (self::entityManager()->getMetadataFactory()->getAllMetadata() as $metadata) {
            $classes[$metadata->getName()] = true;
        }

        return $classes;
    }
}
