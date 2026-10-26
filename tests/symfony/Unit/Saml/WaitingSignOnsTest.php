<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Saml;

use Beffroi\Bundle\Saml\WaitingSignOns;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * beffroi/saml, spec/saml.md S-18, section 6.4 step 3: a request waiting for a login is kept in the HTTP session of the
 * browser that sent it, under a reference this provider drew, for the tenant it was sent to.
 */
final class WaitingSignOnsTest extends TestCase
{
    private Session $httpSession;

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->httpSession = new Session(new MockArraySessionStorage());
        $this->tenant = Fixtures::tenant();
    }

    /**
     * S-18: the request is found under its reference, whole.
     */
    #[Test]
    public function aRequestKeptIsFoundUnderItsReference(): void
    {
        // Given
        $reference = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());

        // When / Then
        static::assertEquals(SignOnRequests::request(), new WaitingSignOns()->find($this->httpSession, $this->tenant, $reference));
    }

    /**
     * S-18: the reference is 32 bytes drawn from random_bytes(), in base64url.
     */
    #[Test]
    public function aReferenceIsThirtyTwoBytesInBase64Url(): void
    {
        // When
        $reference = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());

        // Then
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $reference);
    }

    /**
     * S-18: a reference is drawn again for each request.
     */
    #[Test]
    public function aReferenceIsDrawnForEachRequest(): void
    {
        // Given
        $first = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());

        // When
        $second = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());

        // Then
        static::assertNotSame($first, $second);
    }

    /**
     * S-18: a request of another tenant is not found, without telling why.
     */
    #[Test]
    public function aRequestOfAnotherTenantIsNotFound(): void
    {
        // Given
        $reference = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());

        // When / Then
        static::assertNull(new WaitingSignOns()->find($this->httpSession, Fixtures::tenant('globex'), $reference));
    }

    /**
     * S-18: a request answered is forgotten, and the others wait.
     */
    #[Test]
    public function aRequestForgottenIsNotFoundAndTheOthersWait(): void
    {
        // Given
        $forgotten = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());
        $waiting = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request(relayState: 'state-2'));

        // When
        new WaitingSignOns()->forget($this->httpSession, $forgotten);

        // Then
        static::assertSame(
            [null, 'state-2'],
            [
                new WaitingSignOns()->find($this->httpSession, $this->tenant, $forgotten),
                new WaitingSignOns()->find($this->httpSession, $this->tenant, $waiting)?->relayState,
            ],
        );
    }

    /**
     * The last request forgotten leaves nothing in the session.
     */
    #[Test]
    public function theLastRequestForgottenLeavesNothing(): void
    {
        // Given
        $reference = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request());

        // When
        new WaitingSignOns()->forget($this->httpSession, $reference);

        // Then
        static::assertFalse($this->httpSession->has(WaitingSignOns::SESSION_KEY));
    }

    /**
     * Section 7: eight requests wait in one browser at most, the oldest forgotten first.
     */
    #[Test]
    public function theOldestRequestIsForgottenBeyondEight(): void
    {
        // Given
        $references = [];
        foreach (range(1, 9) as $request) {
            $references[] = new WaitingSignOns()->keep($this->httpSession, $this->tenant, SignOnRequests::request(relayState: 'state-' . $request));
        }

        // When
        $oldest = new WaitingSignOns()->find($this->httpSession, $this->tenant, $references[0]);

        // Then
        static::assertSame([null, 'state-2'], [$oldest, new WaitingSignOns()->find($this->httpSession, $this->tenant, $references[1])?->relayState]);
    }

    /**
     * S-18: what the session holds that is not a request kept by this provider is nothing.
     */
    #[Test]
    public function whatIsNotARequestIsNothing(): void
    {
        // Given
        $this->httpSession->set(WaitingSignOns::SESSION_KEY, [
            'edited' => [
                'tenant' => $this->tenant->id->toRfc4122(),
                'request' => ['id' => 'x'],
            ],
            'malformed' => 'a string',
        ]);

        // When / Then
        static::assertSame(
            [null, null],
            [
                new WaitingSignOns()->find($this->httpSession, $this->tenant, 'edited'),
                new WaitingSignOns()->find($this->httpSession, $this->tenant, 'malformed'),
            ],
        );
    }
}
