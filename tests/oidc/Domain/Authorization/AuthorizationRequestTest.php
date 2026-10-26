<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §4.2: the validated request answers the questions the interaction asks (scope, prompt)
 * and knows where an error raised later goes; the response mode is query.
 */
final class AuthorizationRequestTest extends TestCase
{
    private Client $client;

    private RedirectUri $redirectUri;

    private AuthorizationRequest $request;

    protected function setUp(): void
    {
        $this->client = Clients::public(Fixtures::tenant());
        $this->redirectUri = new RedirectUri('https://spa.example/callback');
        $this->request = new AuthorizationRequest(
            $this->client,
            $this->redirectUri,
            new Scopes([Scope::openid(), new Scope('profile')]),
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', new Sha256CodeChallengeMethod()),
            'af0ifjsldkj',
            'n-0S6_WzA2Mj',
            [Prompt::Login],
        );
    }

    #[Test]
    public function itKnowsTheScopesItAsksFor(): void
    {
        // When / Then
        static::assertTrue($this->request->scopes->has(new Scope('profile')));
        static::assertFalse($this->request->scopes->has(new Scope('email')));
    }

    #[Test]
    public function itKnowsThePromptsItAsksFor(): void
    {
        // When / Then
        static::assertTrue($this->request->hasPrompt(Prompt::Login));
        static::assertFalse($this->request->hasPrompt(Prompt::None));
    }

    #[Test]
    public function itsResponseModeIsQuery(): void
    {
        // When / Then
        static::assertSame('query', $this->request->responseMode);
    }

    #[Test]
    public function itHasNoMaxAgeAndNoClaimsUnlessGiven(): void
    {
        // When / Then
        static::assertNull($this->request->maxAge);
        static::assertNull($this->request->claims);
    }

    #[Test]
    public function itKnowsWhereALaterErrorGoes(): void
    {
        // When
        $target = $this->request->redirectTarget();

        // Then
        static::assertSame($this->client, $target->client);
        static::assertSame($this->redirectUri, $target->redirectUri);
        static::assertSame('af0ifjsldkj', $target->state);
    }

    /**
     * OIDC Core §3.1.2.1 max_age: a session whose latest proof is older than max_age seconds exceeds it, "auth_time +
     * max_age < now"; one exactly max_age seconds old, a younger one, and a request without max_age, do not
     * (beffroi/saml, spec/saml.md S-49).
     */
    #[Test]
    #[DataProvider('provideMaxAges')]
    public function itSaysWhetherASessionExceedsItsMaxAge(?int $maxAge, bool $exceeded): void
    {
        // Given
        $request = new AuthorizationRequest(
            $this->client,
            $this->redirectUri,
            new Scopes([Scope::openid()]),
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', new Sha256CodeChallengeMethod()),
            'af0ifjsldkj',
            'n-0S6_WzA2Mj',
            maxAge: $maxAge,
        );
        $session = Fixtures::session(authenticatedAt: Fixtures::now()->modify('-60 seconds'));

        // When / Then
        static::assertSame($exceeded, $request->maxAgeExceededBy($session, Fixtures::now()));
    }

    /**
     * @return iterable<string, array{?int, bool}>
     */
    public static function provideMaxAges(): iterable
    {
        yield 'a second shorter than the age of the session' => [59, true];
        yield 'the age of the session' => [60, false];
        yield 'a second longer' => [61, false];
        yield 'none' => [null, false];
    }
}
