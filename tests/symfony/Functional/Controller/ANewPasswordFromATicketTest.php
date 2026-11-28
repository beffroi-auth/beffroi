<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Application\Ticket\PasswordTicketIssue;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Domain\Ticket\PasswordTicket;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\PasswordTicketRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0026
 */
final class ANewPasswordFromATicketTest extends BrowserTestCase
{
    private const string IN_USE = 'nine quiet lanterns drift over the harbour';

    private const string POSED = 'seven brass owls guard the winter orchard';

    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        $this->alice = self::userWithPassword('alice', self::IN_USE);
        self::reload();
    }

    #[Test]
    public function theLinkOpensAPageThatNamesTheAccountItIsFor(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $page = $this->ticketPage($issued);

        // Then
        static::assertStringContainsString('alice', self::string($page->filter('p')->first()->text()));
        static::assertCount(1, $page->filter('form[data-password="ticket"]'));
    }

    #[Test]
    public function thePasswordPosedIsTheOneTheAccountHoldsAfterwards(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->pose($issued, self::POSED, self::POSED);

        // Then
        static::assertTrue(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($this->passwordOfAlice()->hash, self::POSED));
    }

    /**
     * RFC 8265 §4.2.3
     */
    #[Test]
    public function aPasswordTypedAgainInAnotherFormConfirmsIt(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->pose($issued, "seven brass owls\u{00A0}guard the winter orchard", self::POSED);

        // Then
        static::assertTrue(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($this->passwordOfAlice()->hash, self::POSED));
    }

    #[Test]
    public function theBrowserGoesOnToTheAccountWhereItSignsIn(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->pose($issued, self::POSED, self::POSED);

        // Then
        static::assertSame([Response::HTTP_SEE_OTHER, '/account'], [
            $this->browser->getResponse()->getStatusCode(),
            $this->browser->getResponse()->headers->get('Location'),
        ]);
    }

    #[Test]
    public function everySessionOfThePersonEndsWithTheSecretItOpenedWith(): void
    {
        // Given
        $session = $this->signIn($this->alice);
        $issued = $this->issue();

        // When
        $this->pose($issued, self::POSED, self::POSED);

        // Then
        self::reload();
        $again = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($session->id) ?? static::fail('The session is gone.');
        static::assertSame(SessionEnd::User, $again->endedBy);
    }

    #[Test]
    public function aTicketSpentOpensNothingAnyMore(): void
    {
        // Given
        $issued = $this->issue();
        $this->pose($issued, self::POSED, self::POSED);

        // When
        $this->browser->request('GET', $this->path($issued));

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aLinkThatOpensNothingSaysOneFlatSentence(): void
    {
        // When
        $page = $this->browser->request('GET', '/password/' . Uuid::v7()->toRfc4122() . '/not-the-value-of-any-link');

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, 'password_ticket_refused'],
            [$this->browser->getResponse()->getStatusCode(), $page->filter('[data-error]')->attr('data-error')],
        );
    }

    #[Test]
    #[DataProvider('provideRefusedPasswords')]
    public function aPasswordRefusedIsSaidAndTheTicketStillOpens(string $posed, string $again, string $refusal): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->pose($issued, $posed, $again);

        // Then
        static::assertSame([$refusal, false], [$this->afterTheForm()->filter('[data-error]')->attr('data-error'), $this->ticketOf($issued)->isSpent()]);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideRefusedPasswords(): iterable
    {
        yield 'two passwords that differ' => [self::POSED, 'seven brass owls guard the summer orchard', 'not_confirmed'];
        yield 'a password too short' => ['owls', 'owls', 'too_short'];
        yield 'the password in use' => [self::IN_USE, self::IN_USE, 'same_as_before'];
        yield 'a tabulation, which the profile refuses' => [
            "my cat is a \u{0009}by and a long one",
            "my cat is a \u{0009}by and a long one",
            'disallowed_character',
        ];
    }

    #[Test]
    public function aFormWithoutItsTokenChangesNothing(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->browser->request('POST', $this->path($issued), [
            'new_password' => self::POSED,
            'new_password_again' => self::POSED,
        ]);

        // Then
        static::assertTrue(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->verify($this->passwordOfAlice()->hash, self::IN_USE));
    }

    /**
     * @return IssuedTicket<PasswordTicket>
     */
    private function issue(): IssuedTicket
    {
        $alice = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($this->alice->id) ?? static::fail('The person is gone.');
        $issued = self::service('test.beffroi.password_tickets', PasswordTicketIssue::class)->issue($alice, self::context());
        self::forgetEvents();

        return $issued;
    }

    /**
     * @param IssuedTicket<PasswordTicket> $issued
     */
    private function path(IssuedTicket $issued): string
    {
        return '/password/' . $issued->ticket->id->toRfc4122() . '/' . $issued->value;
    }

    /**
     * @param IssuedTicket<PasswordTicket> $issued
     */
    private function ticketPage(IssuedTicket $issued): Crawler
    {
        $crawler = $this->browser->request('GET', $this->path($issued));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * @param IssuedTicket<PasswordTicket> $issued
     */
    private function pose(IssuedTicket $issued, string $posed, string $again): void
    {
        $token = $this->ticketPage($issued)->filter('form[data-password="ticket"] input[name="_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', $this->path($issued), [
            '_token' => $token,
            'new_password' => $posed,
            'new_password_again' => $again,
        ]);
    }

    /**
     * @param IssuedTicket<PasswordTicket> $issued
     */
    private function ticketOf(IssuedTicket $issued): PasswordTicket
    {
        self::reload();

        return (
            self::service('test.beffroi.password_ticket_store', PasswordTicketRepositoryInterface::class)
                ->find($issued->ticket->id) ?? static::fail('The ticket is gone.')
        );
    }

    private function passwordOfAlice(): PasswordCredential
    {
        self::reload();
        foreach (self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($this->alice) as $credential) {
            if ($credential instanceof PasswordCredential) {
                return $credential;
            }
        }

        return static::fail('Alice holds no password.');
    }
}
