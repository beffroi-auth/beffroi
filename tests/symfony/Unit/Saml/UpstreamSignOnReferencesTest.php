<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\UpstreamSignOnReferences;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use function sprintf;

/**
 * beffroi/saml S-51, section 7, issue #820: the reference a sign-on at an upstream identity provider starts under,
 * drawn by the login page for one login and one provider, taken once and within its life.
 */
final class UpstreamSignOnReferencesTest extends TestCase
{
    private const string PROVIDER = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

    private const string ANOTHER_PROVIDER = 'https://idp.example.org/saml';

    /**
     * The reference drawn, which a case of a data provider cannot know.
     */
    private const string DRAWN = 'the reference drawn';

    /**
     * S-51, section 7: a reference is 32 bytes of random_bytes() in base64url, another at each drawing.
     */
    #[Test]
    public function aReferenceIsDrawnAnewForEachSignOn(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $first = $references->issue($httpSession, self::interaction(), self::PROVIDER, Fixtures::now());

        // When
        $second = $references->issue($httpSession, self::interaction(), self::PROVIDER, Fixtures::now());

        // Then
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $second);
        static::assertNotSame($first, $second);
    }

    /**
     * S-51: the sign-on of a login presented the reference drawn for it, at the provider it was drawn for, is taken.
     */
    #[Test]
    public function theSignOnTakesTheReferenceDrawnForIt(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $interaction = self::interaction();
        $reference = $references->issue($httpSession, $interaction, self::PROVIDER, Fixtures::now());

        // When / Then
        static::assertTrue($references->take($httpSession, $interaction, self::PROVIDER, $reference, Fixtures::now()));
    }

    /**
     * S-51: a reference that is not the one drawn, an empty one, or the one drawn presented at another provider, is
     * refused.
     */
    #[Test]
    #[DataProvider('provideReferencesNotDrawn')]
    public function aReferenceNotDrawnForTheSignOnIsRefused(string $presented, string $identityProvider): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $drawn = $references->issue($httpSession, null, self::PROVIDER, Fixtures::now());

        // When / Then
        static::assertFalse($references->take($httpSession, null, $identityProvider, $presented === self::DRAWN ? $drawn : $presented, Fixtures::now()));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideReferencesNotDrawn(): iterable
    {
        yield 'another' => ['Ab3xQ0kQ1n0oG2d9V5m8Zr4wY7tL6pHcEeFsUjKiN1o', self::PROVIDER];
        yield 'an empty one' => ['', self::PROVIDER];
        yield 'at another provider' => [self::DRAWN, self::ANOTHER_PROVIDER];
    }

    /**
     * S-51: a reference starts one sign-on, and is refused the second time it is presented.
     */
    #[Test]
    public function aReferenceIsTakenOnce(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $reference = $references->issue($httpSession, null, self::PROVIDER, Fixtures::now());
        $references->take($httpSession, null, self::PROVIDER, $reference, Fixtures::now());

        // When / Then
        static::assertFalse($references->take($httpSession, null, self::PROVIDER, $reference, Fixtures::now()));
    }

    /**
     * S-51: a reference is forgotten at its first presentation whatever was presented, so that the reference drawn
     * is refused once another was presented in its place.
     */
    #[Test]
    public function aReferenceIsForgottenWhateverWasPresented(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $reference = $references->issue($httpSession, null, self::PROVIDER, Fixtures::now());
        $references->take($httpSession, null, self::PROVIDER, 'Ab3xQ0kQ1n0oG2d9V5m8Zr4wY7tL6pHcEeFsUjKiN1o', Fixtures::now());

        // When / Then
        static::assertFalse($references->take($httpSession, null, self::PROVIDER, $reference, Fixtures::now()));
    }

    /**
     * S-51: the reference of the login a page waits for starts no sign-on of an interaction, whose own reference is
     * kept apart, and stays the page's.
     */
    #[Test]
    public function eachLoginKeepsItsOwnReference(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $interaction = self::interaction();
        $references->issue($httpSession, $interaction, self::PROVIDER, Fixtures::now());
        $page = $references->issue($httpSession, null, self::PROVIDER, Fixtures::now());

        // When / Then
        static::assertSame([false, true], [
            $references->take($httpSession, $interaction, self::PROVIDER, $page, Fixtures::now()),
            $references->take($httpSession, null, self::PROVIDER, $page, Fixtures::now()),
        ]);
    }

    /**
     * S-51: a login that draws another reference forgets the one it drew before.
     */
    #[Test]
    public function aLoginDrawingAnotherReferenceForgetsTheOneBefore(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $interaction = self::interaction();
        $first = $references->issue($httpSession, $interaction, self::PROVIDER, Fixtures::now());
        $references->issue($httpSession, $interaction, self::PROVIDER, Fixtures::now());

        // When / Then
        static::assertFalse($references->take($httpSession, $interaction, self::PROVIDER, $first, Fixtures::now()));
    }

    /**
     * S-51, section 7: a browser keeps the references of eight logins at most, the oldest forgotten first, a reference
     * drawn again for a login counting as the newest.
     */
    #[Test]
    public function eightReferencesAreKeptAtMost(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $first = self::interaction();
        $second = self::interaction();
        $references->issue($httpSession, $first, self::PROVIDER, Fixtures::now());
        $ofTheSecond = $references->issue($httpSession, $second, self::PROVIDER, Fixtures::now());
        $ofTheFirst = $references->issue($httpSession, $first, self::PROVIDER, Fixtures::now());

        // When
        for ($login = 0; $login < (UpstreamSignOnReferences::MAX_KEPT - 1); ++$login) {
            $references->issue($httpSession, self::interaction(), self::PROVIDER, Fixtures::now());
        }

        // Then
        static::assertSame([true, false], [
            $references->take($httpSession, $first, self::PROVIDER, $ofTheFirst, Fixtures::now()),
            $references->take($httpSession, $second, self::PROVIDER, $ofTheSecond, Fixtures::now()),
        ]);
    }

    /**
     * S-51, section 7: a reference is taken within its life alone, the redirection that carries it being followed at
     * once.
     */
    #[Test]
    #[DataProvider('provideLives')]
    public function aReferenceIsTakenWithinItsLifeAlone(int $seconds, bool $taken): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $reference = $references->issue($httpSession, null, self::PROVIDER, Fixtures::now());

        // When / Then
        static::assertSame($taken, $references->take(
            $httpSession,
            null,
            self::PROVIDER,
            $reference,
            Fixtures::now()->modify(sprintf('+%d seconds', $seconds)),
        ));
    }

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function provideLives(): iterable
    {
        yield 'at the end of its life' => [UpstreamSignOnReferences::LIFE, true];
        yield 'a second past it' => [UpstreamSignOnReferences::LIFE + 1, false];
    }

    /**
     * S-51: a reference past its life leaves the HTTP session when the references of the browser are written next, its
     * sign-on never reached.
     */
    #[Test]
    public function aReferencePastItsLifeLeavesTheSession(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $references = new UpstreamSignOnReferences();
        $references->issue($httpSession, self::interaction(), self::PROVIDER, Fixtures::now());
        $later = Fixtures::now()->modify(sprintf('+%d seconds', UpstreamSignOnReferences::LIFE + 1));

        // When
        $reference = $references->issue($httpSession, null, self::PROVIDER, $later);

        // Then
        static::assertSame(
            [':page' => ['reference' => $reference, 'identity_provider' => self::PROVIDER, 'issued_at' => $later->getTimestamp()]],
            $httpSession->get(UpstreamSignOnReferences::SESSION_KEY),
        );
    }

    /**
     * S-51: what the HTTP session holds under the key of the references and is no reference of a login starts nothing.
     */
    #[Test]
    #[DataProvider('provideStoredValuesThatAreNoReferences')]
    public function whatIsNoReferenceOfALoginStartsNothing(mixed $stored): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $httpSession->set(UpstreamSignOnReferences::SESSION_KEY, $stored);

        // When / Then
        static::assertFalse(new UpstreamSignOnReferences()->take($httpSession, null, self::PROVIDER, 'a-reference', Fixtures::now()));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideStoredValuesThatAreNoReferences(): iterable
    {
        $now = Fixtures::now()->getTimestamp();

        yield 'no map' => ['a-reference'];
        yield 'a reference alone' => [[':page' => 'a-reference']];
        yield 'a reference that is no string' => [[':page' => ['reference' => ['a-reference'], 'identity_provider' => self::PROVIDER, 'issued_at' => $now]]];
        yield 'a provider that is no string' => [[':page' => ['reference' => 'a-reference', 'identity_provider' => null, 'issued_at' => $now]]];
        yield 'an instant that is no number' => [[':page' => ['reference' => 'a-reference', 'identity_provider' => self::PROVIDER, 'issued_at' => 'now']]];
    }

    private static function interaction(): Interaction
    {
        $tenant = Fixtures::tenant();

        return new Interaction(
            Secrets::draw(),
            $tenant,
            Requests::authorization(Clients::public($tenant)),
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }
}
