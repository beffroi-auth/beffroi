<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Administration;

use function array_map;
use App\Tests\Symfony\Functional\AppKernel;
use App\Tests\Symfony\Functional\Controller\PasskeyTestCase;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: an administrator signs in at the provider of the suite with a passkey, through the client the test
 * kernel declares for the administration API, and holds a token bound to the key of Proofs; the API answers in a
 * kernel of its own, the kernel of a process whose plane is the administration (config_test_administration.yml), on
 * the database and the keys of the provider kernel.
 */
abstract class AdministrationTestCase extends PasskeyTestCase
{
    protected const string CLIENT = 'administration-app';

    protected const string REDIRECT_URI = 'https://administration.test/callback';

    protected const string API = 'https://admin.op.test';

    protected const string SCOPE = 'openid profile';

    /**
     * The origin of the issuer of the test kernel, which a proof names in its "htu" (RFC 9449 §4.3).
     */
    protected const string ISSUER = 'https://op.test';

    /**
     * A proof is used once (RFC 9449 §11.1), so each one made here carries an identifier of its own.
     */
    private static int $proofs = 0;

    private ?AppKernel $administration = null;

    protected function tearDown(): void
    {
        $this->administration?->shutdown();
        $this->administration = null;
        parent::tearDown();
    }

    /**
     * The person a member of the group the test kernel names to administer its tenant, a membership the tenant holds.
     */
    protected static function administers(User $user): GroupMembership
    {
        $group = new Group(Uuid::v7(), self::tenant(), 'administrators', GroupSource::Local, Clock::get()->now());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($group);
        $membership = new GroupMembership(Uuid::v7(), $group, $user, GroupSource::Local, Clock::get()->now());
        self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class)->save($membership);

        return $membership;
    }

    /**
     * The person taken out of every group they are in, as a directory that removes them would.
     */
    protected static function leavesTheirGroups(User $user): void
    {
        $memberships = self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class);
        foreach (self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($user) as $membership) {
            $memberships->remove($membership);
        }
    }

    /**
     * The access token of an administrator who signed in with a passkey, for the API unless another resource or none
     * is named, bound to the key of Proofs.
     */
    protected function administratorToken(User $administrator, ?string $resource = self::API): string
    {
        return self::string($this->administratorTokens($administrator, $resource)['access_token'] ?? null);
    }

    /**
     * What the token endpoint answers the sign-in of an administrator with a passkey, for the API unless another
     * resource or none is named, bound to the key of Proofs.
     *
     * @return array<array-key, mixed>
     */
    protected function administratorTokens(User $administrator, ?string $resource = self::API, string $scope = self::SCOPE): array
    {
        self::signingKey();
        $device = self::device();
        self::administers($administrator);
        $this->enrol($administrator, $device);
        $code = $this->codeAfterAPasskeyLogin($device, $resource, $scope);
        $this->browser->request('POST', '/token', self::tokenParameters($code), server: [
            'HTTP_DPOP' => self::proof('POST', self::ISSUER . '/token'),
        ]);

        return self::json($this->browser->getResponse());
    }

    /**
     * RFC 6749 §6: the refresh of the tokens of the client of the API, proving the key of Proofs.
     */
    protected function refreshed(string $refreshToken): Response
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => self::CLIENT,
            ],
            server: [
                'HTTP_DPOP' => self::proof('POST', self::ISSUER . '/token'),
            ],
        );

        return $this->browser->getResponse();
    }

    protected function codeAfterAPasskeyLogin(SoftwareAuthenticator $device, ?string $resource = self::API, string $scope = self::SCOPE): string
    {
        return self::redirectedQuery($this->afterAPasskeyLogin($device, $resource, $scope))['code'] ?? static::fail('The client got no code.');
    }

    /**
     * A browser that holds no session asks for the API, its person signs in with the passkey, and the interaction
     * goes on to the client.
     */
    protected function afterAPasskeyLogin(SoftwareAuthenticator $device, ?string $resource = self::API, string $scope = self::SCOPE): Response
    {
        $this->forgetTheBrowser();
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::CLIENT, [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => $scope,
            ...(
                $resource === null
                    ? []
                    : [
                        'resource' => $resource,
                    ]
            ),
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->loginWithPasskey($interaction, $device);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        return $this->browser->getResponse();
    }

    /**
     * @return array<string, string>
     */
    protected static function tokenParameters(string $code): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => self::CLIENT,
        ];
    }

    /**
     * A request of the method given to the API, answered by the kernel of a process of its plane: under "DPoP" with
     * the proof of the key of Proofs when a token is presented and proven, under "DPoP" without a proof when it is
     * presented and not proven, and carrying the body given as a document of the type given.
     *
     * @param array<string, string> $query
     */
    protected function api(
        string $path,
        ?string $token,
        bool $proven = true,
        array $query = [],
        string $method = 'GET',
        ?string $content = null,
        string $contentType = 'application/json',
    ): Response {
        $server = [
            'HTTPS' => 'on',
            'HTTP_HOST' => 'admin.op.test',
            'HTTP_ACCEPT' => 'application/json',
        ];
        if ($content !== null) {
            $server['CONTENT_TYPE'] = $contentType;
        }
        if ($token !== null) {
            $server['HTTP_AUTHORIZATION'] = 'DPoP ' . $token;
            if ($proven) {
                $server['HTTP_DPOP'] = self::proof($method, self::API . $path, $token);
            }
        }
        $kernel = $this->administration ??= self::administrationKernel();
        $request = Request::create(self::API . $path, $method, $query, server: $server, content: $content);
        $response = $kernel->handle($request);
        $kernel->terminate($request, $response);

        return $response;
    }

    /**
     * The routes the kernel of a process of the plane of the administration loads, by name: the method a request of
     * each one is sent with, the first it answers or GET for one that answers every method, and its path.
     *
     * @return array<string, array{string, string}>
     */
    protected function routesOfTheApi(): array
    {
        $kernel = $this->administration ??= self::administrationKernel();
        $router = $kernel->getContainer()->get('router');
        static::assertInstanceOf(RouterInterface::class, $router);
        $routes = [];
        foreach ($router->getRouteCollection()->all() as $name => $route) {
            $routes[$name] = [$route->getMethods()[0] ?? 'GET', $route->getPath()];
        }

        return $routes;
    }

    /**
     * The members of that name of the document an answer carries, null for each it does not.
     *
     * @param list<string> $names
     *
     * @return list<mixed>
     */
    protected static function members(Response $response, array $names): array
    {
        $document = json_decode((string) $response->getContent(), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($document);

        return array_map(static fn (string $name): mixed => $document[$name] ?? null, $names);
    }

    /**
     * The acts of that name an administrator did, each as the person it concerns and the administrator, by their subjects.
     *
     * @return list<array{?string, ?string}>
     */
    protected static function authored(string $name): array
    {
        $acts = self::entityManager()->getRepository(JournalEntry::class)->findBy(['act' => $name]);

        $administrators = [];
        foreach ($acts as $act) {
            if ($act->author instanceof AnAdministrator) {
                $administrators[] = [$act->subject?->value, $act->author->subject->value];
            }
        }

        return $administrators;
    }

    /**
     * A service of the kernel of the plane of the administration, by the public alias the test kernel gives it.
     *
     * @template T of object
     *
     * @param class-string<T> $type
     *
     * @return T
     */
    protected function administrationService(string $id, string $type): object
    {
        $kernel = $this->administration ??= self::administrationKernel();
        $service = $kernel->getContainer()->get($id);
        static::assertInstanceOf($type, $service);

        return $service;
    }

    private static function administrationKernel(): AppKernel
    {
        $kernel = new AppKernel('test_administration', false);
        $kernel->boot();

        return $kernel;
    }

    private static function proof(string $method, string $url, ?string $token = null): string
    {
        return Proofs::proof($method, $url, Clock::get()->now(), $token, [
            'jti' => 'administration-proof-' . self::$proofs++,
        ]);
    }
}
