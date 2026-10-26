<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleSignOn;

use function array_map;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\SingleSignOn\AttributeRelease;
use Beffroi\Saml\Domain\ServiceProvider\AttributeMapping;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\RecordingLogger;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

/**
 * spec/saml.md S-16, section 6.4 step 6: the attributes the declaration maps, from the claims the provider serves,
 * and nothing else.
 */
final class AttributeReleaseTest extends TestCase
{
    private const string MAIL = 'urn:oid:0.9.2342.19200300.100.1.3';

    private const string DISPLAY_NAME = 'urn:oid:2.16.840.1.113730.3.1.241';

    private RecordingLogger $logger;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
    }

    /**
     * S-16: one attribute per mapping, under the name, the format and the friendly name of the mapping, in the order
     * of the declaration, and none of the claims nobody mapped.
     */
    #[Test]
    public function theMappedClaimsAreReleasedUnderTheirMapping(): void
    {
        // Given
        $release = $this->release(['email' => 'alice@example.com', 'name' => 'Alice Liddell', 'given_name' => 'Alice']);

        // When
        $released = $release->of(self::declaration(), Fixtures::user());

        // Then
        static::assertEquals(
            [
                new ReleasedAttribute(self::MAIL, AttributeNameFormat::Uri, 'mail', [new AttributeValue('alice@example.com')]),
                new ReleasedAttribute(self::DISPLAY_NAME, AttributeNameFormat::Uri, 'displayName', [new AttributeValue('Alice Liddell')]),
            ],
            $released,
        );
    }

    /**
     * S-16: a claim the user does not hold sends no attribute.
     */
    #[Test]
    public function aClaimTheUserDoesNotHoldSendsNothing(): void
    {
        // Given
        $release = $this->release(['name' => 'Alice Liddell', 'email' => null]);

        // When
        $released = $release->of(self::declaration(), Fixtures::user());

        // Then
        static::assertSame([self::DISPLAY_NAME], array_map(static fn (ReleasedAttribute $attribute): string => $attribute->name, $released));
    }

    /**
     * S-16: a claim whose values are none, an empty list, sends no attribute.
     */
    #[Test]
    public function aClaimWithoutValuesSendsNothing(): void
    {
        // Given
        $release = $this->release(['name' => [], 'email' => 'alice@example.com']);

        // When
        $released = $release->of(self::declaration(), Fixtures::user());

        // Then
        static::assertSame([self::MAIL], array_map(static fn (ReleasedAttribute $attribute): string => $attribute->name, $released));
    }

    /**
     * S-16, issue #670: a value holding a character XML does not carry is not sent, neither cut nor rewritten, and
     * the sign-on goes on with the other attributes.
     */
    #[Test]
    public function aClaimHoldingWhatXmlDoesNotCarryIsNotSent(): void
    {
        // Given
        $release = $this->release(['name' => "Ali\0ce", 'email' => 'alice@example.com']);

        // When
        $released = $release->of(self::declaration(), Fixtures::user());

        // Then
        static::assertSame([self::MAIL], array_map(static fn (ReleasedAttribute $attribute): string => $attribute->name, $released));
    }

    /**
     * S-16: the refusal is written to the log, naming the service provider, the claim and the rule, never the value.
     */
    #[Test]
    public function aClaimNotSentIsWrittenToTheLogWithoutItsValue(): void
    {
        // Given
        $release = $this->release(['name' => "Ali\0ce"]);

        // When
        $release->of(self::declaration(), Fixtures::user());

        // Then
        static::assertEquals(
            [[
                'level' => LogLevel::WARNING,
                'message' => 'The claim "{claim}" is not sent to the SAML service provider "{service_provider}": {rule}',
                'context' => [
                    'claim' => 'name',
                    'service_provider' => ServiceProviderDocuments::SIGNED,
                    'rule' => 'An attribute value holds only the characters of XML 1.0, in UTF-8: no NUL, no other control character but the tab, the line feed and the carriage return, no surrogate, no U+FFFE or U+FFFF (spec/saml.md S-16).',
                ],
            ]],
            $this->logger->records,
        );
    }

    /**
     * S-16: a claim that is a JSON object, the address, is not sent.
     */
    #[Test]
    public function aClaimThatIsAnObjectIsNotSent(): void
    {
        // Given
        $release = $this->release(['address' => ['locality' => 'Lyon']]);
        $declaration = self::declaration([new AttributeMapping('address', 'postalAddress', AttributeNameFormat::Basic)]);

        // When
        $released = $release->of($declaration, Fixtures::user());

        // Then
        static::assertSame([], $released);
    }

    /**
     * A declaration that maps nothing asks for no claim.
     */
    #[Test]
    public function aDeclarationThatMapsNothingReleasesNothing(): void
    {
        // Given
        $release = $this->release(['email' => 'alice@example.com']);

        // When
        $released = $release->of(self::declaration([]), Fixtures::user());

        // Then
        static::assertSame([], $released);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function release(array $claims): AttributeRelease
    {
        return new AttributeRelease(new FixedClaims($claims), $this->logger);
    }

    /**
     * @param list<AttributeMapping>|null $attributes
     */
    private static function declaration(?array $attributes = null): ServiceProvider
    {
        return new ServiceProvider(
            ServiceProviderDocuments::SIGNED,
            new MetadataLocation('/etc/saml/sp.xml'),
            [],
            $attributes ?? [
                new AttributeMapping('email', self::MAIL, AttributeNameFormat::Uri, 'mail'),
                new AttributeMapping('name', self::DISPLAY_NAME, AttributeNameFormat::Uri, 'displayName'),
            ],
        );
    }
}
