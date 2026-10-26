<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * CSP Level 3 §6.1, §6.3.2: the answer of a page that may send the browser to a client names the origin
 * of that client among the targets a form of it may be submitted to, whatever policy the answer carries,
 * and the answer of a page that may answer no client names none.
 */
final class FormTargetTest extends TestCase
{
    private const string ENFORCED = 'Content-Security-Policy';

    private const string REPORTED = 'Content-Security-Policy-Report-Only';

    private const string REDIRECT_URI = 'https://client.example.com/callback';

    private const string ORIGIN = 'https://client.example.com';

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providePoliciesOfAPageThatMayAnswerAClient(): iterable
    {
        yield 'the one directive, which named this provider' => [
            "form-action 'self'",
            "form-action 'self' " . self::ORIGIN,
        ];
        yield 'among the directives of a deployment, which keep their place and their sources' => [
            "default-src 'none'; script-src 'self'; form-action 'self'; frame-ancestors 'none'",
            "default-src 'none'; script-src 'self'; form-action 'self' " . self::ORIGIN . "; frame-ancestors 'none'",
        ];
        yield 'a directive that refused every submission, which may name no source beside it' => [
            "form-action 'none'",
            'form-action ' . self::ORIGIN,
        ];
        yield 'a directive naming another client, which keeps it' => [
            "form-action 'self' https://other.example.com",
            "form-action 'self' https://other.example.com " . self::ORIGIN,
        ];
        yield 'a directive that already named this one, which is named once' => [
            "form-action 'self' " . self::ORIGIN,
            "form-action 'self' " . self::ORIGIN,
        ];
        yield 'a name written in another case, a directive being matched without regard to case' => [
            "FORM-ACTION 'self'",
            "FORM-ACTION 'self' " . self::ORIGIN,
        ];
    }

    #[Test]
    #[DataProvider('providePoliciesOfAPageThatMayAnswerAClient')]
    public function theAnswerOfAPageThatMayAnswerAClientNamesTheOriginOfThatClient(string $policy, string $expected): void
    {
        // Given
        $target = new RedirectUri(self::REDIRECT_URI);

        // When
        $response = self::answer($policy, $target);

        // Then
        static::assertSame($expected, $response->headers->get(self::ENFORCED));
    }

    /**
     * A policy that names no "form-action" allows every submission: the directive falls back to no other
     * (CSP Level 3 §6.1), so there is nothing to complete and the policy is the one the page wrote.
     */
    #[Test]
    public function thePolicyOfAPageThatRestrictsNoSubmissionIsTheOneThePageWrote(): void
    {
        // Given
        $policy = "img-src 'self' https://logo.example.com; frame-ancestors 'none'";

        // When
        $response = self::answer($policy, new RedirectUri(self::REDIRECT_URI));

        // Then
        static::assertSame($policy, $response->headers->get(self::ENFORCED));
    }

    /**
     * A page of the account, and a login a page of the provider asked for: no client is answered, and the
     * policy of the answer says so.
     */
    #[Test]
    public function thePolicyOfAPageThatAnswersNoClientNamesNoOrigin(): void
    {
        // Given
        $policy = "default-src 'none'; form-action 'self'";

        // When
        $response = self::answer($policy, null);

        // Then
        static::assertSame($policy, $response->headers->get(self::ENFORCED));
    }

    /**
     * A deployment that only reports gets the same answer: a report of the one submission this provider
     * makes on purpose would say nothing to anybody.
     */
    #[Test]
    public function thePolicyThatOnlyReportsIsCompletedToo(): void
    {
        // Given
        $target = new RedirectUri(self::REDIRECT_URI);

        // When
        $response = self::answer("form-action 'self'", $target, self::REPORTED);

        // Then
        static::assertSame("form-action 'self' " . self::ORIGIN, $response->headers->get(self::REPORTED));
    }

    /**
     * Two clients are two origins, and the same client named twice is one: a page names what it may
     * answer, and a policy says what it allows one time.
     */
    #[Test]
    public function aPageThatMayAnswerTwoClientsNamesBothOfThemOnce(): void
    {
        // Given
        $listener = new FormTarget();
        $request = Request::create('https://op.test/login');
        $listener->mayEndAt($request, new RedirectUri(self::REDIRECT_URI));
        $listener->mayEndAt($request, new RedirectUri('https://other.example.com/cb'));
        $listener->mayEndAt($request, new RedirectUri(self::REDIRECT_URI));

        // When
        $response = self::answered($listener, $request, new Response('a page', Response::HTTP_OK, [
            self::ENFORCED => "form-action 'self'",
        ]));

        // Then
        static::assertSame(
            "form-action 'self' " . self::ORIGIN . ' https://other.example.com',
            $response->headers->get(self::ENFORCED),
        );
    }

    /**
     * beffroi/saml S-36, the security review of 20 October 2026 (finding C-2): what a page names is written into the
     * header as it is, so a source that is not a scheme, a host and a port is refused where the page names it rather
     * than pasted into the policy, where a ';' would end the directive and start one of its own, "sandbox" freezing
     * the page, and a ',' a policy of its own.
     */
    #[Test]
    #[DataProvider('provideSourcesThatAreNoOrigin')]
    public function aSourceThatIsNoOriginIsRefusedWhereThePageNamesIt(string $source): void
    {
        // Given
        $listener = new FormTarget();
        $request = Request::create('https://op.test/logout');

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A page names an origin in its Content-Security-Policy as a scheme, a host and a port, and nothing else, which would be written into the header as it is (CSP Level 3 §2.3.1, beffroi/saml S-36).');

        // When
        $listener->mayReach($request, $source);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSourcesThatAreNoOrigin(): iterable
    {
        yield 'a host that carries a directive' => ['https://sp.example.org;sandbox'];
        yield 'a host that carries a second policy' => ['https://sp.example.org,sandbox'];
        yield 'a host that carries a space' => ['https://sp.example.org sandbox'];
        yield 'a keyword' => ["'unsafe-inline'"];
        yield 'two sources' => ["'unsafe-inline' https://sp.example.org"];
        yield 'a path' => ['https://sp.example.org/slo'];
        yield 'no host' => ['javascript://'];
    }

    /**
     * CSP Level 3 §2.3.1: an origin on a port, on an IPv4 address or an IPv6 literal, is a source a page may name.
     */
    #[Test]
    #[DataProvider('provideOrigins')]
    public function anOriginIsNamed(string $origin): void
    {
        // Given
        $listener = new FormTarget();
        $request = Request::create('https://op.test/logout');
        $listener->mayReach($request, $origin);

        // When
        $response = self::answered($listener, $request, new Response('a page', Response::HTTP_OK, [self::ENFORCED => "form-action 'self'"]));

        // Then
        static::assertSame("form-action 'self' " . $origin, $response->headers->get(self::ENFORCED));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'a name and a port' => ['https://sp.example.org:8443'];
        yield 'the loopback address of a native client' => ['http://127.0.0.1:51004'];
        yield 'an IPv6 literal' => ['https://[2001:db8::1]'];
    }

    private static function answer(string $policy, ?RedirectUri $target, string $header = self::ENFORCED): Response
    {
        $listener = new FormTarget();
        $request = Request::create('https://op.test/login');
        if ($target !== null) {
            $listener->mayEndAt($request, $target);
        }

        return self::answered($listener, $request, new Response('a page', Response::HTTP_OK, [$header => $policy]));
    }

    private static function answered(FormTarget $listener, Request $request, Response $response): Response
    {
        $listener->onKernelResponse(new ResponseEvent(
            static::createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            $response,
        ));

        return $response;
    }
}
