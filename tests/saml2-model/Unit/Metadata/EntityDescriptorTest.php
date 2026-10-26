<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: an entity descriptor, its entity ID a URI of M-6, its roles carrying that entity ID (SAML Metadata
 * §2.3.2).
 */
final class EntityDescriptorTest extends TestCase
{
    /**
     * Section 5.3: every field, kept as given.
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // Given
        $validUntil = new DateTimeImmutable('2026-10-30T00:00:00Z');
        $idp = $this->identityProvider('https://entity.example.com');
        $sp = $this->serviceProvider('https://entity.example.com');

        // When
        $descriptor = new EntityDescriptor('https://entity.example.com', $validUntil, $idp, $sp, 86_400);

        // Then
        static::assertSame(
            ['https://entity.example.com', $validUntil, $idp, $sp, 86_400],
            [
                $descriptor->entityId,
                $descriptor->validUntil,
                $descriptor->identityProvider,
                $descriptor->serviceProvider,
                $descriptor->cacheDuration,
            ],
        );
    }

    /**
     * Section 5.3: no validUntil, no role and no cacheDuration, by default.
     */
    #[Test]
    public function itHasNoValidUntilNoRoleAndNoCacheDurationByDefault(): void
    {
        // When
        $descriptor = new EntityDescriptor('https://entity.example.com');

        // Then
        static::assertSame([null, null, null, null], [
            $descriptor->validUntil,
            $descriptor->identityProvider,
            $descriptor->serviceProvider,
            $descriptor->cacheDuration,
        ]);
    }

    /**
     * Section 5.3: the shortest cacheDuration it carries is one second.
     */
    #[Test]
    public function itKeepsACacheDurationOfOneSecond(): void
    {
        // When / Then
        static::assertSame(1, new EntityDescriptor('https://entity.example.com', cacheDuration: 1)->cacheDuration);
    }

    /**
     * Section 5.3: a cacheDuration is a number of seconds, one at least, a programming error of the caller otherwise.
     */
    #[Test]
    #[DataProvider('provideCacheDurationsRefused')]
    public function itRefusesACacheDurationUnderOneSecond(int $cacheDuration): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The cacheDuration of an entity descriptor is a number of seconds, one at least (section 5.3).');

        // When
        new EntityDescriptor('https://entity.example.com', cacheDuration: $cacheDuration);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideCacheDurationsRefused(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    /**
     * M-6, section 6.5 step 1: the entity ID is an absolute URI.
     */
    #[Test]
    public function itRefusesARelativeEntityId(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new EntityDescriptor('entity');
    }

    /**
     * Section 5.3: the identity provider carries the entity ID of its descriptor.
     */
    #[Test]
    public function itRefusesAnIdentityProviderOfAnotherEntity(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The identity provider carries the entity ID of its descriptor (section 5.3).');

        // When
        new EntityDescriptor('https://entity.example.com', null, $this->identityProvider('https://other.example.com'));
    }

    /**
     * Section 5.3: the service provider carries the entity ID of its descriptor.
     */
    #[Test]
    public function itRefusesAServiceProviderOfAnotherEntity(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The service provider carries the entity ID of its descriptor (section 5.3).');

        // When
        new EntityDescriptor(
            'https://entity.example.com',
            null,
            null,
            $this->serviceProvider('https://other.example.com'),
        );
    }

    private function identityProvider(string $entityId): IdentityProvider
    {
        return new IdentityProvider(
            $entityId,
            [],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://entity.example.com/sso')],
        );
    }

    private function serviceProvider(string $entityId): ServiceProvider
    {
        return new ServiceProvider($entityId, [], [], new IndexedEndpoints([
            new IndexedEndpoint(Binding::HttpPost, 'https://entity.example.com/acs', 0),
        ]));
    }
}
