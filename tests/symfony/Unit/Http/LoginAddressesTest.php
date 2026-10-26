<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Http\LoginTarget;
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
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;
use function sprintf;

/**
 * beffroi/saml S-61: the step of the address of the login a page of the provider asks for is asked again for the next
 * page that asks for one, whatever was typed for the login before. S-68: the address of a federated domain is kept for
 * the sign-on of that login alone, taken once.
 */
final class LoginAddressesTest extends TestCase
{
    #[Test]
    public function aPageThatAsksForALoginAsksForTheAddressAgain(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->pass($httpSession, null, 'bob@umbrella.example');
        $urls = static::createStub(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturn('/login');
        $targets = new LoginTarget(new InteractionPages(static::createStub(Environment::class), $urls), $addresses);

        // When
        $targets->sendToLogin($httpSession, 'beffroi_interaction_account');

        // Then
        static::assertFalse($addresses->passed($httpSession, null));
    }

    /**
     * S-68: the address sent on for a login is what its sign-on takes.
     */
    #[Test]
    public function theSignOnTakesTheAddressSentOn(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, null, 'alice@Bücher.example', Fixtures::now());

        // When / Then
        static::assertSame('alice@Bücher.example', $addresses->takeSent($httpSession, null, Fixtures::now()));
    }

    /**
     * S-68: an address is taken once, and a second sign-on of the same login takes none.
     */
    #[Test]
    public function anAddressIsTakenOnce(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $interaction = self::interaction();
        $addresses->sendOn($httpSession, $interaction, 'alice@example.org', Fixtures::now());
        $addresses->takeSent($httpSession, $interaction, Fixtures::now());

        // When / Then
        static::assertNull($addresses->takeSent($httpSession, $interaction, Fixtures::now()));
    }

    /**
     * S-68: the address of one login is not taken by the sign-on of another, whose address is its own.
     */
    #[Test]
    public function eachLoginKeepsItsOwnAddress(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $interaction = self::interaction();
        $addresses->sendOn($httpSession, $interaction, 'alice@example.org', Fixtures::now());
        $addresses->sendOn($httpSession, null, 'bob@example.org', Fixtures::now());

        // When / Then
        static::assertSame(['alice@example.org', null], [
            $addresses->takeSent($httpSession, $interaction, Fixtures::now()),
            $addresses->takeSent($httpSession, self::interaction(), Fixtures::now()),
        ]);
    }

    /**
     * S-68, section 7: a browser keeps the addresses of eight logins at most, the oldest forgotten first, the address
     * sent on again for a login counting as the newest.
     */
    #[Test]
    public function eightAddressesAreKeptAtMost(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $first = self::interaction();
        $second = self::interaction();
        $addresses->sendOn($httpSession, $first, 'first@example.org', Fixtures::now());
        $addresses->sendOn($httpSession, $second, 'second@example.org', Fixtures::now());
        $addresses->sendOn($httpSession, $first, 'first@example.org', Fixtures::now());

        // When
        for ($login = 0; $login < (LoginAddresses::MAX_KEPT - 1); ++$login) {
            $addresses->sendOn($httpSession, self::interaction(), 'other@example.org', Fixtures::now());
        }

        // Then
        static::assertSame(['first@example.org', null], [
            $addresses->takeSent($httpSession, $first, Fixtures::now()),
            $addresses->takeSent($httpSession, $second, Fixtures::now()),
        ]);
    }

    /**
     * S-68: back to the step of the address, the address sent on for that login is forgotten with what was typed.
     */
    #[Test]
    public function theAddressSentOnIsForgottenWithTheStep(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, null, 'alice@example.org', Fixtures::now());

        // When
        $addresses->forget($httpSession, null);

        // Then
        static::assertNull($addresses->takeSent($httpSession, null, Fixtures::now()));
    }

    /**
     * S-68: what the HTTP session holds under the key of the addresses and is no address of a login is read as none.
     */
    #[Test]
    #[DataProvider('provideStoredValuesThatAreNoAddresses')]
    public function whatIsNoAddressOfALoginIsNone(mixed $stored): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $httpSession->set(LoginAddresses::SENT_SESSION_KEY, $stored);

        // When / Then
        static::assertNull(new LoginAddresses()->takeSent($httpSession, null, Fixtures::now()));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideStoredValuesThatAreNoAddresses(): iterable
    {
        yield 'no map' => [':page'];
        yield 'an address alone' => [[':page' => 'alice@example.org']];
        yield 'an address that is no string' => [[':page' => ['address' => ['alice@example.org'], 'sent_at' => Fixtures::now()->getTimestamp()]]];
        yield 'an instant that is no number' => [[':page' => ['address' => 'alice@example.org', 'sent_at' => 'now']]];
    }

    /**
     * S-68, section 7: the address kept for a sign-on waits as long as a request for a login, and is taken by no
     * sign-on once that wait is over.
     */
    #[Test]
    #[DataProvider('provideWaits')]
    public function anAddressIsTakenWithinItsWaitAlone(int $seconds, ?string $taken): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, null, 'alice@example.org', Fixtures::now());

        // When / Then
        static::assertSame($taken, $addresses->takeSent($httpSession, null, Fixtures::now()->modify(sprintf('+%d seconds', $seconds))));
    }

    /**
     * @return iterable<string, array{int, ?string}>
     */
    public static function provideWaits(): iterable
    {
        yield 'at the end of its wait' => [LoginAddresses::SENT_WAIT, 'alice@example.org'];
        yield 'a second past it' => [LoginAddresses::SENT_WAIT + 1, null];
    }

    /**
     * S-68: an address whose wait is over leaves the HTTP session when the addresses of the browser are written next,
     * its sign-on never reached.
     */
    #[Test]
    public function anAddressPastItsWaitLeavesTheSession(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, self::interaction(), 'alice@example.org', Fixtures::now());

        // When
        $addresses->sendOn($httpSession, null, 'bob@example.org', Fixtures::now()->modify(sprintf('+%d seconds', LoginAddresses::SENT_WAIT + 1)));

        // Then
        static::assertSame(
            [':page' => ['address' => 'bob@example.org', 'sent_at' => Fixtures::now()->getTimestamp() + LoginAddresses::SENT_WAIT + 1]],
            $httpSession->get(LoginAddresses::SENT_SESSION_KEY),
        );
    }

    /**
     * S-68: the page that waited for a login served, the address kept for the sign-on of that login leaves with it.
     */
    #[Test]
    public function thePageServedTakesTheAddressOfItsLoginWithIt(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());
        $addresses = new LoginAddresses();
        $addresses->sendOn($httpSession, null, 'alice@example.org', Fixtures::now());
        $urls = static::createStub(UrlGeneratorInterface::class);
        $targets = new LoginTarget(new InteractionPages(static::createStub(Environment::class), $urls), $addresses);

        // When
        $targets->forget($httpSession);

        // Then
        static::assertSame([], $httpSession->get(LoginAddresses::SENT_SESSION_KEY));
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
