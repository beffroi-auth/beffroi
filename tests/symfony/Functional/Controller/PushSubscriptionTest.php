<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_decode;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function strlen;
use function strtr;
use Symfony\Component\HttpFoundation\Response;

/**
 * Push API §4, RFC 8292 §3.2, architecture §5.2, §5.6: the page where a user says which of their browsers
 * this provider may reach, over HTTP. The browser is handed the application server key of the tenant, it
 * hands back what its push service gave it, and it is taken out from the same page.
 */
final class PushSubscriptionTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    /**
     * §3.2: the browser is handed the uncompressed point of the active key, which is what it subscribes
     * with, and the page names the worker that will receive.
     */
    #[Test]
    public function thePageHandsTheBrowserTheApplicationServerKey(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        $form = $crawler->filter('form[data-push="subscribe"]');
        $key = self::string($form->attr('data-application-server-key'));
        static::assertSame(65, strlen(self::string(base64_decode(strtr($key, '-_', '+/'), true))));
        static::assertSame('/push-worker.js', $form->attr('data-worker-url'));
    }

    /**
     * A tenant whose key has not been drawn has nothing to hand out, and the page says this provider
     * reaches nobody this way rather than offering a button that cannot work.
     */
    #[Test]
    public function aTenantWithoutAKeyHandsOutNothing(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertSame('', $crawler->filter('form[data-push="subscribe"]')->attr('data-application-server-key'));
        static::assertStringContainsString(
            'This provider does not tell browsers.',
            $crawler->filter('p[data-push-unsupported]')->text(),
        );
    }

    /**
     * Architecture §5.2: the page says why this browser was not added, one sentence per reason the script
     * of the bundle can name, each hidden until it names that one. The reasons are somebody else's to act
     * on: a permission to give back, a certificate to trust, a push service to reach.
     */
    #[Test]
    #[DataProvider('provideFailures')]
    public function thePageSaysWhyTheBrowserWasNotAdded(string $reason, string $sentence): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        $paragraph = $crawler->filter('p[data-push-error="' . $reason . '"]');
        static::assertCount(1, $paragraph);
        // hidden carries no value, so the attribute is there when it reads as the empty string and absent when it reads as null
        static::assertSame('', $paragraph->attr('hidden'));
        static::assertStringContainsString($sentence, $paragraph->text());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideFailures(): iterable
    {
        yield 'permission' => ['permission', 'it did not allow notifications'];
        yield 'worker' => ['worker', 'could not be installed'];
        yield 'subscription' => ['subscription', 'its push service refused the subscription'];
    }

    /**
     * Push API §4: what the browser hands back is kept against the key it was handed, and the page lists
     * it.
     */
    #[Test]
    public function aBrowserThatSubscribesIsListed(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        $key = self::applicationServerKey();

        // When
        $this->subscribe();

        // Then
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT);
        static::assertInstanceOf(PushSubscription::class, $subscription);
        static::assertSame(self::PUBLIC_KEY, $subscription->publicKey);
        static::assertSame(self::AUTH_SECRET, $subscription->authSecret);
        static::assertSame($key->kid, $subscription->applicationServerKid);
        static::assertSame('Alice at the counter', $subscription->label);
    }

    /**
     * The page comes back with what is subscribed, and what the user called it.
     */
    #[Test]
    public function thePageListsWhatIsSubscribed(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();
        $this->subscribe();

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertCount(1, $crawler->filter('table[data-subscriptions="1"] tr[data-subscription]'));
        // the name is the field it is corrected in, so it is read there and not in the text of the row
        static::assertSame(
            ['Alice at the counter'],
            $crawler->filter('tr[data-subscription] form[data-subscription="rename"] input[name="label"]')->extract(['value']),
        );
    }

    /**
     * Push API §4: the same browser subscribing again hands back the endpoint it already had, so the row it
     * has is what changes. It is the one path where a row is read and written in the same request, which is
     * what a second object over one identity is refused by, and what no test against an in-memory store can
     * see.
     */
    #[Test]
    public function aBrowserThatSubscribesAgainChangesTheRowItHas(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $first = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->subscribe(label: 'Alice at home');

        // Then
        $again = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('The browser is gone.');
        static::assertTrue($first->id->equals($again->id));
        static::assertEquals($first->createdAt, $again->createdAt);
        static::assertSame('Alice at home', $again->label);
        static::assertCount(1, self::subscriptions()->findActiveByUser(self::reloaded($alice)));
    }

    /**
     * RFC 8030 §7.3, Push API §4: a browser the user had taken out is reachable again when it subscribes
     * again, having just said so, and it does not come back beside itself.
     */
    #[Test]
    public function aBrowserTakenOutIsReachableAgainWhenItSubscribesAgain(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');
        $this->browser->request('POST', '/account/notifications/' . $subscription->id->toRfc4122() . '/revoke', [
            '_token' => $this->token('form[data-subscription="revoke"]'),
        ]);

        // When
        $this->subscribe();

        // Then
        static::assertCount(1, self::subscriptions()->findActiveByUser(self::reloaded($alice)));
    }

    /**
     * RFC 8030 §2: what could not be a push endpoint is refused, and the page says so.
     */
    #[Test]
    public function anEndpointThatIsNotOneIsRefused(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();

        // When
        $this->subscribe(endpoint: 'http://push.example/f/AbCdEf');

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="refused"]'));
    }

    /**
     * Decision 0002: a browser taken out is reached by nobody again and its row stays.
     */
    #[Test]
    public function aBrowserTakenOutIsReachedByNobody(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->browser->request('POST', '/account/notifications/' . $subscription->id->toRfc4122() . '/revoke', [
            '_token' => $this->token('form[data-subscription="revoke"]'),
        ]);

        // Then
        static::assertSame([], self::subscriptions()->findActiveByUser(self::reloaded($alice)));
    }

    /**
     * The page of the account needs a signed-in user, and a browser without a session is told to sign in.
     */
    #[Test]
    public function aBrowserWithoutASessionIsToldToSignInFirst(): void
    {
        // When
        $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The service worker is served at the root of the pages of the bundle, so that its scope covers the
     * page it opens (Service Workers §3.1.1).
     */
    #[Test]
    public function theServiceWorkerIsServedAtTheRootOfThePages(): void
    {
        // When
        $this->browser->request('GET', '/push-worker.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
    }

    /**
     * Architecture §5.2: what tells one browser from another is a name its holder wrote, corrected in the
     * line where it is read.
     */
    #[Test]
    public function aBrowserIsNamedAgainFromTheLineItIsReadIn(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->rename($subscription->id->toRfc4122(), 'Alice at home');

        // Then
        static::assertSame('Alice at home', self::subscriptions()->find($subscription->id)?->label);
    }

    /**
     * What a browser may be called is the rule of the row that holds it, read on the server, and the page
     * says what was refused once (issue #481).
     */
    #[Test]
    public function aNameABrowserDoesNotHoldIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->rename($subscription->id->toRfc4122(), '   ');

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="invalid_label"]'));
    }

    /**
     * Somebody else's browser is not found, as it is not taken out either.
     */
    #[Test]
    public function theBrowserOfSomebodyElseIsNotNamed(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');
        $token = $this->token('form[data-subscription="rename"]');
        $this->signIn(self::userWithPassword('grace', self::PASSWORD));

        // When
        $this->browser->request('POST', '/account/notifications/' . $subscription->id->toRfc4122() . '/name', [
            '_token' => $token,
            'label' => 'Grace at the counter',
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Push API §4: the page carries the digest of the endpoint of every browser it lists, which is what
     * the script of the bundle recognises the browser reading the page by. The endpoint itself is on no
     * page: a digest is what this provider compares too (PushSubscription::digestOf).
     */
    #[Test]
    public function eachRowCarriesTheDigestOfItsEndpointAndNotTheEndpoint(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertSame([$subscription->endpointHash], $crawler->filter('tr[data-subscription]')->extract(['data-endpoint']));
        static::assertStringNotContainsString(self::ENDPOINT, self::string($this->browser->getResponse()->getContent()));
    }

    private function rename(string $id, string $label): void
    {
        $this->browser->request('POST', '/account/notifications/' . $id . '/name', [
            '_token' => $this->token('form[data-subscription="rename"]'),
            'label' => $label,
        ]);
    }

    private function subscribe(string $endpoint = self::ENDPOINT, string $label = 'Alice at the counter'): void
    {
        $this->browser->request('POST', '/account/notifications', [
            '_token' => $this->token('form[data-push="subscribe"]'),
            'endpoint' => $endpoint,
            'p256dh' => self::PUBLIC_KEY,
            'auth' => self::AUTH_SECRET,
            'label' => $label,
        ]);
    }

    /**
     * The token the page renders, taken from the form that posts it.
     */
    private function token(string $form): string
    {
        $crawler = $this->browser->request('GET', '/account/notifications');

        return self::string($crawler->filter($form . ' input[name="_token"]')->attr('value'));
    }

    /**
     * The user as the rows hold them, the browser having rebooted the kernel between two requests.
     */
    private static function reloaded(User $user): User
    {
        self::reload();

        return self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
    }

    private static function subscriptions(): PushSubscriptionRepositoryInterface
    {
        self::reload();

        return self::service('test.beffroi.push_subscriptions', PushSubscriptionRepositoryInterface::class);
    }
}
