<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use function array_fill;
use function array_filter;
use Closure;
use function count;
use function explode;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function str_contains;
use function str_starts_with;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * A user is read when the administrator asks for one, and their sessions and their journal when the administrator asks
 * for them: each read is an act of their journal (decisions 0022 and 0038), which the screen says first.
 */
final class UsersSectionTest extends TestCase
{
    private const string LINK = 'https://op.example/enrol/t-1/v-1';

    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function nothingIsReadOfAPersonUntilTheAdministratorAsks(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        $this->screen->open('section.users');

        // Then
        static::assertSame(
            [[], true],
            [
                array_filter($this->screen->http->requests, static fn (array $request): bool => str_starts_with(
                    $request['url'],
                    FakeProvider::ADMINISTRATION . '/users',
                )),
                str_contains($this->screen->screen(), 'Every read of a person is logged under your name'),
            ],
        );
    }

    #[Test]
    public function aUsernameTypedThenEnterReadsTheUser(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');

        // When
        $this->screen->press("\r");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true, 1], [
            str_contains($screen, 'Alice Liddell'),
            str_contains($screen, 'administrators (local)'),
            preg_match('/passkey +YubiKey/', $screen),
        ]);
    }

    #[Test]
    public function aUsernameThatNamesNobodyIsSaidSo(): void
    {
        // Given
        $this->screen = new SignedInScreen([]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('nobody');

        // When
        $this->screen->press("\r");

        // Then
        static::assertStringContainsString('No user named nobody.', $this->screen->screen());
    }

    /**
     * Once a person is shown, the keys go to what can be read of them, and `s` reads their sessions.
     */
    #[Test]
    public function theSessionsAreReadWhenTheAdministratorAsksForThem(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => [
                'sessions' => [[
                    'id' => 'session-1',
                    'authenticated_at' => '2026-11-04T09:00:00Z',
                    'last_seen_at' => '2026-11-04T09:30:00Z',
                    'expires_at' => '2026-11-04T17:00:00Z',
                    'acr' => 'phr',
                    'methods' => ['hwk', 'user'],
                    'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => 'Lille, France'],
                ]],
            ],
        ]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('s');

        // Then
        static::assertSame(
            [1, 0, true],
            [
                $this->screen->requestsTo('/users/0193-alice/sessions'),
                $this->screen->requestsTo('/users/0193-alice/journal'),
                str_contains($this->screen->screen(), '203.0.113.4'),
            ],
        );
    }

    #[Test]
    public function theJournalIsReadWhenTheAdministratorAsksForIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/journal' => [
                'acts' => [[
                    'id' => 'act-1',
                    'act' => 'user.authenticated',
                    'occurred_at' => '2026-11-04T09:00:00Z',
                    'client' => 'oidc-demo',
                    'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => null],
                ]],
            ],
        ]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('j');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([0, 1], [
            $this->screen->requestsTo('/users/0193-alice/sessions'),
            preg_match('/2026-11-04 09:00 +sign-ins +oidc-demo/', $screen),
        ]);
    }

    /**
     * Decision 0066
     */
    #[Test]
    public function theJournalSaysWhoDidAnActByTheirKindAndWhatNamesThem(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/journal' => [
                'acts' => [[
                    'id' => 'act-1',
                    'act' => 'person.disabled',
                    'occurred_at' => '2026-11-04T09:00:00Z',
                    'client' => null,
                    'author' => ['kind' => 'directory', 'name' => 'Entra'],
                    'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => null],
                ]],
            ],
        ]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('j');

        // Then
        static::assertStringContainsString('directory Entra', $this->screen->screen());
    }

    /**
     * The key that changes a row is on the last line of the screen while its table has the focus.
     */
    #[Test]
    public function theKeyThatRevokesACredentialIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        self::lookUpAlice($this->screen);

        // Then
        static::assertStringContainsString('x  revoke', $this->screen->screen());
    }

    /**
     * Decision 0038: a change of a person is asked to be confirmed, and nothing is sent before it is.
     */
    #[Test]
    public function aChangeIsAskedToBeConfirmedBeforeItIsMade(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('s');

        // When
        $this->screen->press('x');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($this->screen->screen(), 'End the session of alice authenticated 2026-11-04 09:00'),
        ]);
    }

    #[Test]
    public function aSessionIsEndedOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
            'DELETE /users/0193-alice/sessions/session-1' => ['id' => 'session-1', 'ended_at' => '2026-11-04T10:00:00Z'],
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['s', 'x']);

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, false, true], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($screen, '203.0.113.4'),
            str_contains($screen, 'Session of alice ended'),
        ]);
    }

    /**
     * A person whose every session ended holds none the view could list, an expired one that did not end included.
     */
    #[Test]
    public function aPersonWithoutASessionIsSaidToHoldNone(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => ['sessions' => []],
        ]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('s');

        // Then
        static::assertSame([true, true], [
            str_contains($this->screen->screen(), 'Sessions · read logged'),
            str_contains($this->screen->screen(), 'No session.'),
        ]);
    }

    /**
     * A change the administrator did not confirm at once is forgotten, and a `y` pressed later confirms nothing.
     */
    #[Test]
    public function anyOtherKeyThanYForgetsTheChange(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['s', 'x']);

        // When
        $this->screen->press(['n', 'y']);

        // Then
        static::assertSame([0, false], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($this->screen->screen(), 'End the session of alice'),
        ]);
    }

    /**
     * A question left by a key the screen answers before the table, Tab here, is forgotten as well.
     */
    #[Test]
    public function aQuestionTheFocusLeftIsForgotten(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['s', 'x']);

        // When
        $this->screen->press(["\t", "\t", "\t", 'y']);

        // Then
        static::assertSame([0, false], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($this->screen->screen(), 'End the session of alice'),
        ]);
    }

    #[Test]
    public function aCredentialIsRevokedOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'DELETE /users/0193-alice/credentials/credential-1' => [
                'id' => 'credential-1',
                'kind' => 'passkey',
                'name' => 'YubiKey',
                'revoked_at' => '2026-11-04T10:00:00Z',
            ],
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('x');

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, true, true], [
            $this->screen->requestsTo('/users/0193-alice/credentials/credential-1', 'DELETE'),
            str_contains($screen, '2026-11-04 10:00'),
            str_contains($screen, 'The passkey credential YubiKey of alice is revoked'),
        ]);
    }

    /**
     * A password is replaced, never revoked: the screen says so and asks nothing.
     */
    #[Test]
    public function aCredentialNoRevocationAppliesToIsNotOffered(): void
    {
        // Given
        $alice = self::alice();
        $alice['credentials'] = [[
            'id' => 'credential-2',
            'kind' => 'password',
            'revocable' => false,
            'created_at' => '2026-10-01T08:00:00Z',
        ]];
        $this->screen = new SignedInScreen(['/users?username=alice' => $alice]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press(['x', 'y']);

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/credentials/credential-2', 'DELETE'),
            str_contains($this->screen->screen(), 'A password is replaced, never revoked'),
        ]);
    }

    /**
     * The letters the screen answers to are the field's while the administrator types in it.
     */
    #[Test]
    public function theLettersTypedInTheFieldAreTheFieldsOwn(): void
    {
        // Given
        $this->screen = new SignedInScreen([]);
        $this->screen->open('section.users');
        $this->screen->press("\t");

        // When
        $this->screen->type('qr');

        // Then
        static::assertSame([true, true], [$this->screen->shell->typing($this->screen->tui), str_contains($this->screen->screen(), 'Username: qr')]);
    }

    #[Test]
    public function aUsernameTypedInTheFieldOfANewPersonCreatesThem(): void
    {
        // Given
        $this->screen = new SignedInScreen(['POST /users' => self::created(self::dave())]);
        $this->screen->open('section.users');
        $this->screen->press(["\t", "\t"]);
        $this->screen->type('dave');

        // When
        $this->screen->press("\r");

        // Then
        static::assertSame([['{"username":"dave"}'], true], [
            $this->screen->bodiesTo('/users', 'POST'),
            str_contains($this->screen->screen(), 'Account dave created, with no credential'),
        ]);
    }

    /**
     * Decision 0022: the person the API created is shown from its answer, which no read of them follows.
     */
    #[Test]
    public function aPersonCreatedIsShownWithoutReadingThem(): void
    {
        // Given
        $this->screen = new SignedInScreen(['POST /users' => self::created(self::dave())]);
        $this->screen->open('section.users');
        $this->screen->press(["\t", "\t"]);
        $this->screen->type('dave');

        // When
        $this->screen->press("\r");

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users?username=dave'),
            str_contains($this->screen->screen(), 'Person dave'),
        ]);
    }

    #[Test]
    public function aUsernameTheTenantHoldsAlreadyIsSaidSo(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            'POST /users' => static fn (): MockResponse => new MockResponse(
                '{"error":"conflict","error_description":"The tenant has a person of this username already."}',
                ['http_code' => 409],
            ),
        ]);
        $this->screen->open('section.users');
        $this->screen->press(["\t", "\t"]);
        $this->screen->type('alice');

        // When
        $this->screen->press("\r");

        // Then
        static::assertStringContainsString('The username alice is already taken.', $this->screen->screen());
    }

    #[Test]
    public function theKeyThatIssuesAnEnrolmentLinkIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        self::lookUpAlice($this->screen);

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertStringContainsString('passkey link', $lines[count($lines) - 1]);
    }

    /**
     * Decision 0026: a link issued takes away the one the person had not spent, so it is asked first.
     */
    #[Test]
    public function anEnrolmentLinkIsAskedToBeConfirmedBeforeItIsIssued(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('t');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/enrolment-ticket', 'POST'),
            str_contains($this->screen->screen(), 'Issue a link to add a passkey for alice?'),
        ]);
    }

    /**
     * Kitty keyboard protocol, event types: a terminal that reports the release of a key sends it as a key of its own.
     */
    #[Test]
    public function theKeyThatAskedForALinkLetGoKeepsTheQuestion(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/enrolment-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('t');

        // When
        $this->screen->press(["\e[116;1:3u", 'y']);

        // Then
        static::assertSame(1, $this->screen->requestsTo('/users/0193-alice/enrolment-ticket', 'POST'));
    }

    #[Test]
    public function theLinkIsShownAsACodeInPlaceOfThePersonOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/enrolment-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('t');

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, true, true, false], [
            $this->screen->requestsTo('/users/0193-alice/enrolment-ticket', 'POST'),
            str_contains($screen, self::LINK . ' is valid until'),
            str_contains($screen, '▀'),
            str_contains($screen, 'YubiKey 5 NFC'),
        ]);
    }

    /**
     * Decision 0026: a password link ends every session of the person once spent, so it is asked first.
     */
    #[Test]
    public function aPasswordLinkIsAskedToBeConfirmedBeforeItIsIssued(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('p');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/password-ticket', 'POST'),
            str_contains($this->screen->screen(), 'Issue a new password link for alice?'),
        ]);
    }

    #[Test]
    public function thePasswordLinkIsShownAsACodeInPlaceOfThePersonOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/password-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('p');

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, true, true, true], [
            $this->screen->requestsTo('/users/0193-alice/password-ticket', 'POST'),
            str_contains($screen, 'Password link of alice'),
            str_contains($screen, self::LINK . ' is valid until'),
            str_contains($screen, '▀'),
        ]);
    }

    /**
     * Decision 0026: an OTP link revokes the app of the person and ends every session of theirs once spent, so it is asked first.
     */
    #[Test]
    public function anOtpLinkIsAskedToBeConfirmedBeforeItIsIssued(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('o');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/totp-ticket', 'POST'),
            str_contains($this->screen->screen(), 'Issue a new authenticator app link for alice?'),
        ]);
    }

    #[Test]
    public function theOtpLinkIsShownAsACodeInPlaceOfThePersonOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/totp-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('o');

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, true, true, true], [
            $this->screen->requestsTo('/users/0193-alice/totp-ticket', 'POST'),
            str_contains($screen, 'OTP link of alice'),
            str_contains($screen, self::LINK . ' is valid until'),
            str_contains($screen, '▀'),
        ]);
    }

    #[Test]
    public function anyOtherKeyThanYIssuesNoLink(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/enrolment-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('t');

        // When
        $this->screen->press(['n', 'y']);

        // Then
        static::assertSame(0, $this->screen->requestsTo('/users/0193-alice/enrolment-ticket', 'POST'));
    }

    /**
     * The link opens an enrolment on the account of the person: it leaves the screen as soon as the focus leaves it.
     */
    #[Test]
    public function theLinkLeavesTheScreenWithTheFocus(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/enrolment-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['t', 'y']);

        // When
        $this->screen->press("\t");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([false, false, true], [str_contains($screen, self::LINK), str_contains($screen, '▀'), str_contains($screen, 'YubiKey 5 NFC')]);
    }

    #[Test]
    public function enterGivesThePersonBackInPlaceOfTheLink(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'POST /users/0193-alice/enrolment-ticket' => self::created(self::ticket()),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['t', 'y']);

        // When
        $this->screen->press("\r");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([false, true, true], [
            str_contains($screen, self::LINK),
            str_contains($screen, 'YubiKey 5 NFC'),
            str_contains(explode("\n", $screen)[count(explode("\n", $screen)) - 1], 'revoke'),
        ]);
    }

    #[Test]
    public function theKeyThatOpensTheFormOfTheAccountIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        self::lookUpAlice($this->screen);

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertStringContainsString('edit', $lines[count($lines) - 1]);
    }

    #[Test]
    public function eOpensTheFormOfTheAccountWithWhatThePersonHolds(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('e');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, 1, 1], [
            str_contains($screen, 'Account of alice'),
            preg_match('/username +alice/', $screen),
            preg_match('/email +alice@example\.com/', $screen),
        ]);
    }

    #[Test]
    public function theKeysOfTheFormAreSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('e');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame(1, preg_match('/change.*save/', $lines[count($lines) - 1]));
    }

    /**
     * RFC 7396 §2: what the administrator did not change is not in the patch.
     */
    #[Test]
    public function aMemberChangedIsSentAloneInAMergePatchOfTheAccount(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'PATCH /users/0193-alice' => self::account(['name' => 'Alice Liddell', 'email' => 'alice@example.com', 'nickname' => 'Ali']),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(9), "\r"]);
        $this->screen->type('Ali');
        $this->screen->press("\r");

        // When
        $this->screen->press('s');

        // Then
        static::assertSame(['{"claims":{"nickname":"Ali"}}'], $this->screen->bodiesTo('/users/0193-alice', 'PATCH'));
    }

    #[Test]
    public function enterTurnsAVerificationOver(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(2)]);

        // When
        $this->screen->press("\r");

        // Then
        static::assertSame(1, preg_match('/email_verified +yes +to save/', $this->screen->screen()));
    }

    /**
     * RFC 7396 §2: a member of the address is merged into the address the person holds.
     */
    #[Test]
    public function aMemberOfTheAddressIsSentInsideTheAddress(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'PATCH /users/0193-alice' => self::account(['name' => 'Alice Liddell', 'address' => ['locality' => 'Lyon']]),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(20), "\r"]);
        $this->screen->type('Lyon');
        $this->screen->press("\r");

        // When
        $this->screen->press('s');

        // Then
        static::assertSame(['{"claims":{"address":{"locality":"Lyon"}}}'], $this->screen->bodiesTo('/users/0193-alice', 'PATCH'));
    }

    #[Test]
    public function aSavedChangeShowsThePersonAsTheApiAnsweredThem(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'PATCH /users/0193-alice' => self::account(['name' => 'Alice Liddell', 'email' => 'alice@example.com', 'nickname' => 'Ali']),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(9), "\r"]);
        $this->screen->type('Ali');
        $this->screen->press("\r");

        // When
        $this->screen->press('s');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, 1, false, true], [
            str_contains($screen, 'Changes to alice saved.'),
            preg_match('/nickname +Ali/', $screen),
            str_contains($screen, 'Account of alice'),
            str_contains($screen, 'YubiKey 5 NFC'),
        ]);
    }

    #[Test]
    public function aRefusalIsSaidAndTheChangesStayInTheForm(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'PATCH /users/0193-alice' => static fn (): MockResponse => new MockResponse(
                '{"error":"invalid_request","error_description":"The birthdate is a day of the calendar."}',
                ['http_code' => 400],
            ),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(15), "\r"]);
        $this->screen->type('the first of May');
        $this->screen->press("\r");

        // When
        $this->screen->press('s');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, 1], [
            str_contains($screen, 'Nothing was saved: The birthdate is a day of the calendar.'),
            preg_match('/birthdate +the first of May +to save/', $screen),
        ]);
    }

    #[Test]
    public function sWithNothingChangedSaysSoAndWritesNothing(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);
        $this->screen->press('e');

        // When
        $this->screen->press('s');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice', 'PATCH'),
            str_contains($this->screen->screen(), 'Nothing has changed'),
        ]);
    }

    /**
     * The form is the account of the person until the focus leaves it: the access of the person comes back in its place.
     */
    #[Test]
    public function theFormLeavesTheScreenWithTheFocus(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(2), "\r"]);

        // When
        $this->screen->press("\t");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([false, true], [str_contains($screen, 'Account of alice'), str_contains($screen, 'YubiKey 5 NFC')]);
    }

    #[Test]
    public function theFormLeavesTheScreenWhenTheFocusLeavesItsField(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(9), "\r"]);
        $this->screen->type('Ali');

        // When
        $this->screen->press("\t");

        // Then
        static::assertStringNotContainsString('Account of alice', $this->screen->screen());
    }

    #[Test]
    public function whatWasNotSavedLeavesWithTheForm(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['e', ...self::down(2), "\r", "\t", "\t", "\t", "\t"]);

        // When
        $this->screen->press('e');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, false], [str_contains($screen, 'Account of alice'), str_contains($screen, 'to save')]);
    }

    #[Test]
    public function theKeyThatDisablesThePersonIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        self::lookUpAlice($this->screen);

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertMatchesRegularExpression('/ d +disable /', $lines[count($lines) - 1]);
    }

    /**
     * Decision 0038: disabling a person ends every session of theirs, so it is asked first.
     */
    #[Test]
    public function aDisablingIsAskedToBeConfirmedBeforeItIsMade(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('d');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/disabled', 'PUT'),
            str_contains($this->screen->screen(), 'Disable alice?'),
        ]);
    }

    #[Test]
    public function thePersonIsDisabledOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'PUT /users/0193-alice/disabled' => [...self::account(['name' => 'Alice Liddell']), 'enabled' => false],
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('d');

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        $lines = explode("\n", $screen);
        static::assertSame([1, true, 1], [
            $this->screen->requestsTo('/users/0193-alice/disabled', 'PUT'),
            str_contains($screen, 'Account of alice disabled'),
            preg_match('/ d +enable /', $lines[count($lines) - 1]),
        ]);
    }

    #[Test]
    public function aDisabledPersonIsAskedToBeEnabledAgain(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => [...self::alice(), 'enabled' => false]]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('d');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/disabled', 'DELETE'),
            str_contains($this->screen->screen(), 'Enable alice again?'),
        ]);
    }

    #[Test]
    public function aDisabledPersonIsEnabledOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => [...self::alice(), 'enabled' => false],
            'DELETE /users/0193-alice/disabled' => self::account(['name' => 'Alice Liddell']),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('d');

        // When
        $this->screen->press('y');

        // Then
        static::assertSame([1, 0, true], [
            $this->screen->requestsTo('/users/0193-alice/disabled', 'DELETE'),
            $this->screen->requestsTo('/users/0193-alice/disabled', 'PUT'),
            str_contains($this->screen->screen(), 'Account of alice enabled again.'),
        ]);
    }

    /**
     * Decision 0022: the applications a person agreed to are read only when the administrator asks for them.
     */
    #[Test]
    public function theApplicationsAreNotReadBeforeTheAdministratorAsksForThem(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/consents' => self::consentsOfAlice(),
        ]);

        // When
        self::lookUpAlice($this->screen);

        // Then
        static::assertSame(0, $this->screen->requestsTo('/users/0193-alice/consents'));
    }

    #[Test]
    public function theApplicationsAreReadWhenTheAdministratorAsksForThem(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/consents' => self::consentsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('a');

        // Then
        static::assertSame([1, 0, 1], [
            $this->screen->requestsTo('/users/0193-alice/consents'),
            $this->screen->requestsTo('/users/0193-alice/sessions'),
            preg_match('/Invoices +oidc-demo +openid profile/', $this->screen->screen()),
        ]);
    }

    #[Test]
    public function theKeyThatTakesAConsentBackIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/consents' => self::consentsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press('a');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertMatchesRegularExpression('/ x +revoke /', $lines[count($lines) - 1]);
    }

    /**
     * A consent taken back revokes what the application holds under it, so it is asked first.
     */
    #[Test]
    public function takingAConsentBackIsAskedToBeConfirmedFirst(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/consents' => self::consentsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('a');

        // When
        $this->screen->press('x');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/consents/consent-1', 'DELETE'),
            str_contains($this->screen->screen(), 'Revoke the consent alice gave Invoices?'),
        ]);
    }

    #[Test]
    public function aConsentIsTakenBackOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/consents' => self::consentsOfAlice(),
            'DELETE /users/0193-alice/consents/consent-1' => ['id' => 'consent-1', 'client_id' => 'oidc-demo', 'revoked_at' => '2026-11-04T10:00:00Z'],
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['a', 'x']);

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 0, true], [
            $this->screen->requestsTo('/users/0193-alice/consents/consent-1', 'DELETE'),
            preg_match('/Invoices +oidc-demo/', $screen),
            str_contains($screen, 'Consent alice gave Invoices revoked'),
        ]);
    }

    #[Test]
    public function anyOtherKeyThanYTakesNoConsentBack(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/consents' => self::consentsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['a', 'x']);

        // When
        $this->screen->press(['n', 'y']);

        // Then
        static::assertSame([0, false], [
            $this->screen->requestsTo('/users/0193-alice/consents/consent-1', 'DELETE'),
            str_contains($this->screen->screen(), 'Revoke the consent alice gave'),
        ]);
    }

    private static function lookUpAlice(SignedInScreen $screen): void
    {
        $screen->open('section.users');
        $screen->press("\t");
        $screen->type('alice');
        $screen->press("\r");
    }

    /**
     * @return array<string, mixed>
     */
    private static function consentsOfAlice(): array
    {
        return [
            'consents' => [[
                'id' => 'consent-1',
                'client_id' => 'oidc-demo',
                'client_name' => 'Invoices',
                'scope' => 'openid profile',
                'claims' => [],
                'granted_at' => '2026-11-01T08:00:00Z',
                'renewable' => 1,
                'last_renewed_at' => '2026-11-04T09:00:00Z',
                'awaiting' => 0,
            ]],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function sessionsOfAlice(): array
    {
        return [
            'sessions' => [[
                'id' => 'session-1',
                'authenticated_at' => '2026-11-04T09:00:00Z',
                'last_seen_at' => '2026-11-04T09:30:00Z',
                'expires_at' => '2026-11-04T17:00:00Z',
                'acr' => 'phr',
                'methods' => ['hwk', 'user'],
                'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => 'Lille, France'],
            ]],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function alice(): array
    {
        return [
            'id' => '0193-alice',
            'subject' => 'subject-of-alice',
            'username' => 'alice',
            'enabled' => true,
            'source' => 'local',
            'created_at' => '2026-10-01T08:00:00Z',
            'claims' => ['name' => 'Alice Liddell', 'email' => 'alice@example.com'],
            'groups' => [['name' => 'administrators', 'source' => 'local']],
            'credentials' => [[
                'id' => 'credential-1',
                'kind' => 'passkey',
                'name' => 'YubiKey',
                'authenticator' => 'YubiKey 5 NFC',
                'created_at' => '2026-10-01T08:00:00Z',
                'last_used_at' => '2026-11-04T09:00:00Z',
                'revocable' => true,
            ]],
        ];
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return Closure(): MockResponse
     */
    private static function created(array $document): Closure
    {
        return SignedInScreen::answered($document, 201);
    }

    /**
     * The account of alice as a change of it answers, without her groups and her credentials.
     *
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private static function account(array $claims): array
    {
        return [
            'id' => '0193-alice',
            'subject' => 'subject-of-alice',
            'username' => 'alice',
            'enabled' => true,
            'source' => 'local',
            'created_at' => '2026-10-01T08:00:00Z',
            'claims' => $claims,
        ];
    }

    /**
     * The arrow down, pressed that many times.
     *
     * @return list<string>
     */
    private static function down(int $times): array
    {
        return array_fill(0, $times, "\e[B");
    }

    /**
     * @return array<string, mixed>
     */
    private static function ticket(): array
    {
        return ['link' => self::LINK, 'expires_at' => '2026-11-07T10:00:00Z'];
    }

    /**
     * @return array<string, mixed>
     */
    private static function dave(): array
    {
        return [
            'id' => '0193-dave',
            'subject' => 'subject-of-dave',
            'username' => 'dave',
            'enabled' => true,
            'source' => 'local',
            'created_at' => '2026-11-04T10:00:00Z',
            'claims' => [],
            'groups' => [],
            'credentials' => [],
        ];
    }
}
