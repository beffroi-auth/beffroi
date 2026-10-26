<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Http\StepUpOffer;
use Beffroi\Bundle\Saml\UpstreamLoginRequirement;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Authorization\AuthenticationRequirement;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Beffroi\Oidc\Tests\Fixture\Logins;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use DateTimeImmutable;
use function str_repeat;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * beffroi/saml, spec/saml.md S-49, S-58, S-59: what a login at an upstream identity provider is asked, read from the rule
 * of the login page, AuthenticationRequirement, and from nothing written again beside it.
 */
final class UpstreamLoginRequirementTest extends TestCase
{
    private const string BOB_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Ym9i.c2lnbmF0dXJl';

    private Tenant $tenant;

    private User $alice;

    private DateTimeImmutable $now;

    private InMemoryCredentialRepository $credentials;

    private UpstreamLoginRequirement $requirement;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->now = new DateTimeImmutable('2026-09-15T12:00:00+00:00');
        $this->credentials = new InMemoryCredentialRepository();
        $hints = new FakeJwsVerifier();
        $hints->knows($this->tenant, self::BOB_HINT, '{"iss":"https://id.acme.example","sub":"bob-subject","aud":"oidc-demo"}');
        $this->requirement = new UpstreamLoginRequirement(
            new AuthenticationRequirement(Logins::passwordAndPasskey(), $this->credentials, new IdTokenHintVerifier($hints), Subjects::ofAProvider()),
        );
    }

    /**
     * S-49, OIDC Core §3.1.2.1: a browser that holds no session forces a login for prompt=login, and for nothing else,
     * a max_age being measured at the response.
     */
    #[Test]
    #[DataProvider('provideRequestsOfABrowserWithoutASession')]
    public function aBrowserWithoutASessionForcesALoginForPromptLoginAlone(bool $promptLogin, ?int $maxAge, bool $forced): void
    {
        // Given
        $request = Requests::authorization($this->client(), prompts: $promptLogin ? [Prompt::Login] : [], maxAge: $maxAge);

        // When / Then
        static::assertSame($forced, $this->requirement->forcesALogin($this->interaction($request), null, $this->now));
    }

    /**
     * @return iterable<string, array{bool, int|null, bool}>
     */
    public static function provideRequestsOfABrowserWithoutASession(): iterable
    {
        yield 'prompt=login' => [true, null, true];
        yield 'a max_age' => [false, 60, false];
        yield 'neither' => [false, null, false];
    }

    /**
     * S-49: a browser that holds a session forces a login whenever the interaction asks more of that session than it
     * holds, whatever it asks.
     */
    #[Test]
    #[DataProvider('provideWhatTheInteractionAsksOfASession')]
    public function aSignedInBrowserForcesALoginWhenTheInteractionAsksMore(int $maxAge, ?string $hint, bool $forced): void
    {
        // Given
        $request = Requests::authorization($this->client(), maxAge: $maxAge, idTokenHint: $hint);

        // When / Then
        static::assertSame($forced, $this->requirement->forcesALogin($this->interaction($request), $this->session('-1 hour'), $this->now));
    }

    /**
     * @return iterable<string, array{int, string|null, bool}>
     */
    public static function provideWhatTheInteractionAsksOfASession(): iterable
    {
        yield 'a max_age it exceeds' => [60, null, true];
        yield 'an id_token_hint naming another person' => [7200, self::BOB_HINT, true];
        yield 'nothing more than it holds' => [7200, null, false];
    }

    /**
     * S-49, the review of beffroi-auth/beffroi#805: a step-up of a browser signed in forces the login, as a step-up of a
     * page does, so that the session of the provider never answers for one more proof.
     */
    #[Test]
    public function aStepUpOfASignedInBrowserForcesALogin(): void
    {
        // Given
        $this->credentials->save(Fixtures::passkey($this->alice));
        $request = Requests::authorization($this->client(), acrValues: ['phr']);

        // When / Then
        static::assertTrue($this->requirement->forcesALogin($this->interaction($request), $this->session('-1 hour'), $this->now));
    }

    /**
     * S-49: a page asks a person signed in for a fresh proof or for one more, and forces the login; a page asks a
     * browser without a session for a first login, which forces none.
     */
    #[Test]
    public function aPageForcesTheLoginOfABrowserSignedInAlone(): void
    {
        // When / Then
        static::assertSame([true, false], [
            $this->requirement->forcesALogin(null, $this->session('-1 hour'), $this->now),
            $this->requirement->forcesALogin(null, null, $this->now),
        ]);
    }

    /**
     * S-58, OIDC Core §3.1.2.1: a login during the interaction satisfies prompt=login and a max_age; an AuthnInstant
     * before the interaction began does not, compared exactly.
     */
    #[Test]
    #[DataProvider('provideAuthnInstants')]
    public function whatTheClientStillAsksIsReadAgainstTheAuthnInstant(bool $promptLogin, ?int $maxAge, string $authnInstant, ?LoginRequirement $asked): void
    {
        // Given
        $request = Requests::authorization($this->client(), prompts: $promptLogin ? [Prompt::Login] : [], maxAge: $maxAge);

        // When
        $still = $this->requirement->stillAsked(
            $this->interaction($request),
            $this->alice,
            [new AuthenticationMethod('fed'), AuthenticationMethod::password()],
            $this->now->modify($authnInstant),
            null,
            Fixtures::context($this->now),
            $this->now,
        );

        // Then
        static::assertSame($asked, $still);
    }

    /**
     * @return iterable<string, array{bool, int|null, string, LoginRequirement|null}>
     */
    public static function provideAuthnInstants(): iterable
    {
        yield 'prompt=login, at the beginning of the interaction' => [true, null, '-1 minute', null];
        yield 'prompt=login, a second before it' => [true, null, '-61 seconds', LoginRequirement::ReauthenticationRequested];
        yield 'a max_age, within it' => [false, 300, '-2 minutes', null];
        yield 'a max_age, older than it' => [false, 300, '-2 hours', LoginRequirement::MaxAgeExceeded];
        yield 'an AuthnInstant ahead of the clock, dated by it' => [false, 300, '+1 minute', null];
        yield 'nothing asked' => [false, null, '-2 hours', null];
    }

    /**
     * S-58: an id_token_hint naming another person than the provider asserted asks still, whenever that person signed
     * in.
     */
    #[Test]
    public function anotherPersonThanTheHintAsksStill(): void
    {
        // When
        $still = $this->requirement->stillAsked(
            $this->interaction(Requests::authorization($this->client(), idTokenHint: self::BOB_HINT)),
            $this->alice,
            [new AuthenticationMethod('fed')],
            $this->now,
            null,
            Fixtures::context($this->now),
            $this->now,
        );

        // Then
        static::assertSame(LoginRequirement::DifferentUser, $still);
    }

    /**
     * S-58, S-57: the session the browser holds for that person keeps its proofs, the login adding its own, so that a
     * max_age the old proofs exceed is answered by the new one.
     */
    #[Test]
    public function theSessionOfThePersonIsReadWithTheProofsOfTheLogin(): void
    {
        // When
        $still = $this->requirement->stillAsked(
            $this->interaction(Requests::authorization($this->client(), maxAge: 300)),
            $this->alice,
            [new AuthenticationMethod('fed')],
            $this->now->modify('-1 minute'),
            $this->session('-3 hours'),
            Fixtures::context($this->now),
            $this->now,
        );

        // Then
        static::assertNull($still);
    }

    /**
     * S-59: a step-up a page asked for is met by a login that proves one of its classes, with the proofs the session
     * of that person already holds.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    #[Test]
    #[DataProvider('provideStepUps')]
    public function aStepUpIsMetByALoginThatProvesOneOfItsClasses(array $methods, bool $met): void
    {
        // When
        $meets = $this->requirement->meets(
            new StepUpOffer(['2', 'phr'], ['totp']),
            $this->alice,
            $methods,
            $this->now,
            $this->session('-1 hour'),
            Fixtures::context($this->now),
            $this->now,
        );

        // Then
        static::assertSame($met, $meets);
    }

    /**
     * @return iterable<string, array{non-empty-list<AuthenticationMethod>, bool}>
     */
    public static function provideStepUps(): iterable
    {
        yield 'a one-time password beside the password the session holds' => [[new AuthenticationMethod('fed'), new AuthenticationMethod('otp')], true];
        yield 'a federated assertion alone' => [[new AuthenticationMethod('fed')], false];
    }

    private function client(): Client
    {
        return Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
    }

    private function interaction(AuthorizationRequest $request): Interaction
    {
        return new Interaction(str_repeat('A', 43), $this->tenant, $request, null, $this->now->modify('-1 minute'), $this->now->modify('+9 minutes'));
    }

    private function session(string $authenticatedAt): AuthenticationSession
    {
        $at = $this->now->modify($authenticatedAt);

        return Fixtures::session($this->alice, $at, AuthenticationProofs::of(AuthenticationMethod::password(), $at));
    }
}
