<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0002: a person names the source that created it and holds its attributes, local or an upstream
 * provider, and what that source holds a manual description does not change.
 */
final class UserSourceTest extends TestCase
{
    #[Test]
    public function aLocalSourceNamesNoProviderAndHoldsNothing(): void
    {
        // When
        $source = UserSource::local();

        // Then
        static::assertTrue($source->isLocal());
        static::assertNull($source->provider);
        static::assertSame([], $source->claims);
    }

    #[Test]
    public function anUpstreamSourceNamesItsProviderAndTheClaimsItHolds(): void
    {
        // When
        $source = UserSource::upstream('https://idp.acme.example/saml', ['email', 'given_name']);

        // Then
        static::assertFalse($source->isLocal());
        static::assertSame('https://idp.acme.example/saml', $source->provider);
        static::assertSame(['email', 'given_name'], $source->claims);
    }

    #[Test]
    public function aClaimIsHeldOnceInTheOrderItWasNamed(): void
    {
        // When
        $source = UserSource::upstream('workforce', ['family_name', 'email', 'family_name']);

        // Then
        static::assertSame(['family_name', 'email'], $source->claims);
    }

    /**
     * @param list<string> $claims
     */
    #[Test]
    #[DataProvider('provideWhatIsNotASource')]
    public function whatIsNotASourceIsRefused(?string $provider, array $claims, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new UserSource($provider, $claims);
    }

    /**
     * @return iterable<string, array{string|null, list<string>, string}>
     */
    public static function provideWhatIsNotASource(): iterable
    {
        yield 'an unnamed provider' => ['', [], 'An upstream provider that created a person is named.'];
        yield 'an unnamed claim' => ['workforce', ['email', ''], 'A claim an upstream provider holds has a name.'];
        yield 'a local source holding a claim' => [null, ['email'], 'A local source holds no claim of the person it created.'];
    }

    #[Test]
    public function aDescriptionThatChangesAClaimTheSourceHoldsIsRefusedNamingTheProvider(): void
    {
        // Given
        $source = UserSource::upstream('workforce', ['email', 'given_name', 'family_name']);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The upstream provider "workforce" created this person and holds "given_name", "family_name": a manual description does not change what its source holds.');

        // When
        $source->assertLeaves(['nickname', 'given_name', 'family_name']);
    }

    /**
     * @param list<string> $changed
     */
    #[Test]
    #[DataProvider('provideDescriptionsASourceLeaves')]
    public function aDescriptionThatChangesNothingTheSourceHoldsIsLeftToItsAuthor(UserSource $source, array $changed): void
    {
        // When
        $source->assertLeaves($changed);

        // Then
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return iterable<string, array{UserSource, list<string>}>
     */
    public static function provideDescriptionsASourceLeaves(): iterable
    {
        yield 'a claim an upstream provider does not hold' => [UserSource::upstream('workforce', ['email']), ['nickname']];
        yield 'any claim of a local person' => [UserSource::local(), ['email', 'given_name']];
        yield 'a description that changes nothing' => [UserSource::upstream('workforce', ['email']), []];
    }

    #[Test]
    public function anUpstreamSourceIsReadBackFromTheDocumentItWrote(): void
    {
        // Given
        $source = UserSource::upstream('https://idp.acme.example/saml', ['email', 'given_name']);

        // When
        $read = UserSource::fromDocument($source->toDocument());

        // Then
        static::assertEquals($source, $read);
    }

    /**
     * A local source holds nothing, so it writes nothing, and nothing reads back as one.
     */
    #[Test]
    public function aLocalSourceWritesNoDocument(): void
    {
        // When / Then
        static::assertNull(UserSource::local()->toDocument());
    }

    #[Test]
    public function noDocumentReadsBackAsALocalSource(): void
    {
        // When / Then
        static::assertTrue(UserSource::fromDocument(null)->isLocal());
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThisObjectDidNotWrite')]
    public function aDocumentThisObjectDidNotWriteIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        UserSource::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThisObjectDidNotWrite(): iterable
    {
        yield 'no provider' => [
            [
                'claims' => ['email'],
            ],
            'The document of an upstream source names its provider.',
        ];
        yield 'a provider that is not a string' => [
            [
                'provider' => 12,
                'claims' => [],
            ],
            'The member "provider" must be a string or absent.',
        ];
        yield 'claims that are not a list' => [
            [
                'provider' => 'workforce',
                'claims' => 'email',
            ],
            'The member "claims" must be a JSON list.',
        ];
        yield 'a claim that is not a name' => [
            [
                'provider' => 'workforce',
                'claims' => [12],
            ],
            'The claims an upstream provider holds are names.',
        ];
    }

    /**
     * Issue #781: what the provider says now of the claims its source holds is what the profile says; what
     * it does not hold, or does not say, is left as it was.
     */
    #[Test]
    public function anUpstreamSourceRewritesWhatItHoldsAsItsProviderSaysItNow(): void
    {
        // Given
        $source = UserSource::upstream('workforce', ['email', 'given_name', 'family_name']);
        $profile = new Profile(givenName: 'Alice', familyName: 'Liddell', nickname: 'ali');

        // When
        $rewritten = $source->rewrite($profile, [
            'given_name' => 'Alicia',
            'nickname' => 'what the provider does not hold',
        ]);

        // Then
        static::assertEquals(new Profile(givenName: 'Alicia', familyName: 'Liddell', nickname: 'ali'), $rewritten);
    }

    #[Test]
    public function aLocalSourceRewritesNothing(): void
    {
        // Given
        $profile = new Profile(givenName: 'Alice');

        // When
        $rewritten = UserSource::local()->rewrite($profile, [
            'given_name' => 'Alicia',
        ]);

        // Then
        static::assertEquals($profile, $rewritten);
    }
}
