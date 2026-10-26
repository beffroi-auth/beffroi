<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC Core §8.1, modules oidcc-registration-sector-uri and -sector-bad: what a sector sees of a user, end
 * to end. Three clients of the test kernel and two sectors: two clients whose sector is the host of their
 * redirection URI, on two hosts, and a third that registers the document of the first one's host and is
 * therefore of the first one's sector.
 */
final class PairwiseSubjectTest extends BrowserTestCase
{
    private const string SECRET = 'pairwise-secret-of-at-least-32-characters';

    private const string OTHER_SECRET = 'pairwise-other-secret-of-at-least-32-char';

    private const string SECTOR_SECRET = 'pairwise-sector-secret-of-at-least-32-cha';

    private const string REDIRECT_URI = 'https://pairwise.test/callback';

    private const string OTHER_REDIRECT_URI = 'https://other-pairwise.test/callback';

    private const string SECTOR_REDIRECT_URI = 'https://sector-member.test/callback';

    protected function setUp(): void
    {
        parent::setUp();
        self::signingKey();
    }

    /**
     * The property pairwise identifiers exist for: two clients of two sectors hold two strings for one
     * person and cannot find out by comparing them.
     */
    #[Test]
    public function twoSectorsSeeOneUserUnderTwoIdentifiers(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $here = $this->idTokenSubjectOf('pairwise-app', self::REDIRECT_URI, self::SECRET);
        $there = $this->idTokenSubjectOf('pairwise-other-app', self::OTHER_REDIRECT_URI, self::OTHER_SECRET);

        // Then
        static::assertNotSame($here, $there);
    }

    /**
     * OIDC Registration §5: what a sector identifier document is for. A client that registers the document
     * of another host belongs to that host's sector, so one user is one account to both of them.
     */
    #[Test]
    public function twoClientsOfOneSectorSeeOneUserUnderOneIdentifier(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $ofTheHost = $this->idTokenSubjectOf('pairwise-app', self::REDIRECT_URI, self::SECRET);
        $ofTheDocument = $this->idTokenSubjectOf('pairwise-sector-app', self::SECTOR_REDIRECT_URI, self::SECTOR_SECRET);

        // Then
        static::assertSame($ofTheHost, $ofTheDocument);
    }

    /**
     * Decision 0002: a client that registers no kind sees the subject the core keeps, which is what every
     * client of this provider has seen so far. The two are read side by side, of the same user, in the same
     * session.
     */
    #[Test]
    public function aPublicClientSeesTheSubjectTheCoreKeepsAndAPairwiseOneDoesNot(): void
    {
        // Given
        $user = self::user('alice');
        $this->signIn($user);

        // When
        $public = $this->idTokenSubjectOf('native-app', 'http://127.0.0.1/callback', null);
        $pairwise = $this->idTokenSubjectOf('pairwise-app', self::REDIRECT_URI, self::SECRET);

        // Then
        static::assertSame($user->subject->value, $public);
        static::assertNotSame($user->subject->value, $pairwise);
    }

    /**
     * OIDC Core §5.3.2: every document written for a client says the same thing about who it is about. The
     * access token, the UserInfo answer and the ID token of one client carry one identifier.
     */
    #[Test]
    public function everyDocumentWrittenForAClientCarriesItsOwnIdentifier(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $tokens = $this->tokensOf('pairwise-app', self::REDIRECT_URI, self::SECRET);
        $accessToken = self::string($tokens['access_token']);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $subject = self::string(self::claimsOf(self::string($tokens['id_token']))['sub']);
        static::assertSame($subject, self::claimsOf($accessToken)['sub']);
        static::assertSame($subject, self::json($this->browser->getResponse())['sub']);
    }

    /**
     * The way back, through the store: a token whose "sub" is a string no row of the users carries is
     * introspected, and the user it names is found for the client that holds it.
     */
    #[Test]
    public function anAccessTokenOfAPairwiseClientIsIntrospectedAndItsUserFound(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $tokens = $this->tokensOf('pairwise-app', self::REDIRECT_URI, self::SECRET);
        $accessToken = self::string($tokens['access_token']);

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('pairwise-app:' . self::SECRET),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $members = self::json($response);
        static::assertTrue($members['active']);
        static::assertSame(self::claimsOf($accessToken)['sub'], $members['sub']);
    }

    /**
     * Architecture §4.6: the shape the client registered changes who reads the token back and nothing else.
     * An opaque token of a pairwise client is introspected to the identifier its client sees, and the
     * introspection is what a client holding one has instead of reading it.
     */
    #[Test]
    public function anOpaqueTokenOfAPairwiseClientIsIntrospectedToTheIdentifierItsClientSees(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $tokens = $this->tokensOf('pairwise-other-app', self::OTHER_REDIRECT_URI, self::OTHER_SECRET);
        $subject = self::claimsOf(self::string($tokens['id_token']))['sub'];

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => self::string($tokens['access_token']),
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('pairwise-other-app:' . self::OTHER_SECRET),
            ],
        );

        // Then
        $members = self::json($this->browser->getResponse());
        static::assertTrue($members['active'], self::string($this->browser->getResponse()->getContent()));
        static::assertSame($subject, $members['sub']);
    }

    /**
     * What makes the answer above possible: the identifier was written down when the documents were, and
     * the row names the user the sector of that client sees, and nobody to another sector.
     */
    #[Test]
    public function theIdentifierIsWrittenDownForTheSectorAndForNoOther(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $tokens = $this->tokensOf('pairwise-app', self::REDIRECT_URI, self::SECRET);
        $subject = new Subject(self::string(self::claimsOf(self::string($tokens['id_token']))['sub']));

        // When
        self::reload();
        $assigned = self::service('test.beffroi.pairwise_subjects', PairwiseSubjectRepositoryInterface::class);
        $found = $assigned->findUser(self::tenant(), new SectorIdentifier('pairwise.test'), $subject);
        $elsewhere = $assigned->findUser(self::tenant(), new SectorIdentifier('other-pairwise.test'), $subject);

        // Then
        static::assertSame($alice->subject->value, $found?->subject->value);
        static::assertNull($elsewhere);
    }

    /**
     * OIDC Core §3.1.2.1 id_token_hint (issue #838): the ID token a client of pairwise subjects was given names
     * the person signed in, so prompt=none is answered with a code and not with login_required.
     */
    #[Test]
    public function theIdTokenOfAPairwiseClientNamesThePersonSignedInAtTheAuthorizationEndpoint(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $idToken = self::string($this->tokensOf('pairwise-app', self::REDIRECT_URI, self::SECRET)['id_token']);

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('pairwise-app', [
            'redirect_uri' => self::REDIRECT_URI,
            'prompt' => 'none',
            'id_token_hint' => $idToken,
        ]));

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertArrayHasKey('code', $query, $query['error'] ?? '');
    }

    /**
     * RP-Initiated Logout 1.0 §2 (issue #838): the same ID token presented at the end session endpoint names the
     * session the browser holds, which therefore ends without a question.
     */
    #[Test]
    public function theIdTokenOfAPairwiseClientEndsTheSessionWithoutAQuestion(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        $idToken = self::string($this->tokensOf('pairwise-app', self::REDIRECT_URI, self::SECRET)['id_token']);

        // When
        $this->browser->request('GET', '/logout', [
            'id_token_hint' => $idToken,
        ]);

        // Then
        $ended = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertTrue($ended->hasEnded());
    }

    /**
     * CIBA Core §4: the three ways of saying which sector a client is of are wired, and the third is what
     * answers for a client that registers no redirection URI. What no unit test can say is that they are
     * really tagged and composed in the container of a deployment, which is what this reads.
     */
    #[Test]
    public function theSectorOfABackchannelClientIsTheHostOfItsKeys(): void
    {
        // Given
        $client = self::client('pairwise-terminal');

        // When
        $sector = self::service('test.beffroi.sector_identifiers', SectorIdentifiersInterface::class)->sectorOf($client->registration);

        // Then
        static::assertSame('terminal-sector.test', $sector->host);
    }

    /**
     * And a client that registers a redirection URI is of the host it comes back to, whatever its keys
     * say: the source of CIBA Core §4 answers of a client that registered none, and of no other.
     */
    #[Test]
    public function theSectorOfAnOrdinaryClientIsStillTheHostItComesBackTo(): void
    {
        // Given
        $client = self::client('pairwise-app');

        // When
        $sector = self::service('test.beffroi.sector_identifiers', SectorIdentifiersInterface::class)->sectorOf($client->registration);

        // Then
        static::assertSame('pairwise.test', $sector->host);
    }

    /**
     * OIDC Discovery §3: the document names both kinds, because the provider is wired with both. The two
     * modules that judge a sector skip themselves unless it does.
     */
    #[Test]
    public function theDocumentAnnouncesBothKinds(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame(['public', 'pairwise'], self::json($this->browser->getResponse())['subject_types_supported']);
    }

    private function idTokenSubjectOf(string $clientId, string $redirectUri, ?string $secret): string
    {
        return self::string(self::claimsOf(self::string($this->tokensOf($clientId, $redirectUri, $secret)['id_token']))['sub']);
    }

    /**
     * @return array<string, mixed>
     */
    private function tokensOf(string $clientId, string $redirectUri, ?string $secret): array
    {
        $this->signInClient($clientId, $redirectUri, $secret);

        return self::json($this->browser->getResponse());
    }
}
