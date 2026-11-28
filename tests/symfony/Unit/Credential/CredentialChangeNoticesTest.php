<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\CredentialChangeNotices;
use App\Locale\Moments;
use App\Locale\UserTimeZone;
use App\Tests\Symfony\Fixture\CatalogueNotices;
use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\BackupCodesRenewed;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\TenantContact;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * NIST SP 800-63B-4 §4.6
 */
final class CredentialChangeNoticesTest extends TestCase
{
    private User $alice;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
    }

    #[Test]
    public function theNoticeIsWrittenByTheProvider(): void
    {
        // When
        $notice = $this->notices()->of($this->alice, $this->enrolled());

        // Then
        static::assertSame('Acme', $notice->title);
    }

    #[Test]
    public function theSubjectNamesTheTenantAndSaysHowThePersonSignsInChanged(): void
    {
        // When
        $notice = $this->notices()->of($this->alice, $this->enrolled());

        // Then
        static::assertSame('Acme: a change to how you sign in', $notice->subject);
    }

    #[Test]
    #[DataProvider('provideActsTold')]
    public function theNoticeSaysWhatChangedAndWhen(string $act, ?string $kind, string $said): void
    {
        // Given
        $change = new CredentialChange($this->alice, $act, self::moment(), $kind);

        // When
        $notice = $this->notices()->of($this->alice, $change);

        // Then
        static::assertSame(sprintf('%s on %s. If it was not you, open your account.', $said, $this->written('en')), $notice->body);
    }

    /**
     * @return iterable<string, array{string, ?string, string}>
     */
    public static function provideActsTold(): iterable
    {
        yield 'a passkey added' => [CredentialEnrolled::NAME, 'passkey', 'A passkey was added to your account'];
        yield 'an authenticator app added' => [CredentialEnrolled::NAME, 'totp', 'An authenticator app was added to your account'];
        yield 'a first password added' => [CredentialEnrolled::NAME, 'password', 'A password was added to your account'];
        yield 'a passkey removed' => [CredentialRevoked::NAME, 'passkey', 'A passkey was removed from your account'];
        yield 'an authenticator app removed' => [CredentialRevoked::NAME, 'totp', 'An authenticator app was removed from your account'];
        yield 'a password changed' => [PasswordChanged::NAME, 'password', 'The password of your account was changed'];
        yield 'a link to add a passkey issued' => [EnrolmentTicketIssued::NAME, null, 'A link to add a passkey to your account was issued'];
        yield 'backup codes renewed' => [BackupCodesRenewed::NAME, 'totp', 'The backup codes of your account were renewed'];
        yield 'a kind the words do not name' => [CredentialEnrolled::NAME, 'smartcard', 'A way of signing in was added to your account'];
        yield 'an address changed' => [ChannelChangeNotice::ACT, 'email', 'The email address of your account was changed'];
        yield 'a phone number changed' => [ChannelChangeNotice::ACT, 'phone_number', 'The phone number of your account was changed'];
        yield 'a channel the words do not name' => [ChannelChangeNotice::ACT, 'pager', 'A way of reaching you was changed'];
    }

    #[Test]
    public function theNoticeGivesTheContactOfTheTenant(): void
    {
        // Given
        $this->alice->tenant->adoptContact(new TenantContact('security@acme.example'));

        // When
        $notice = $this->notices()->of($this->alice, $this->enrolled());

        // Then
        static::assertSame(
            sprintf('A passkey was added to your account on %s. If it was not you, open your account and contact security@acme.example.', $this->written('en')),
            $notice->body,
        );
    }

    /**
     * Architecture §5.7, OIDC Core §5.1
     */
    #[Test]
    public function theNoticeIsWrittenInTheLanguageOfThePerson(): void
    {
        // Given
        $this->alice->updateProfile(new Profile(locale: 'fr-CA'), Fixtures::now());

        // When
        $notice = $this->notices()->of($this->alice, $this->enrolled());

        // Then
        static::assertSame(
            sprintf('Une passkey a été ajoutée à votre compte le %s. Si ce n\'était pas vous, ouvrez votre compte.', $this->written('fr')),
            $notice->body,
        );
    }

    /**
     * Architecture §5.7, OIDC Core §5.1
     */
    #[Test]
    public function theNoticeIsWrittenOnTheClockOfThePerson(): void
    {
        // Given
        $this->alice->updateProfile(new Profile(zoneinfo: 'Europe/Paris', locale: 'fr'), Fixtures::now());

        // When
        $notice = $this->notices()->of($this->alice, $this->enrolled());

        // Then
        static::assertSame(
            'Une passkey a été ajoutée à votre compte le 22 nov. 2026, 15:05 UTC+1. Si ce n\'était pas vous, ouvrez votre compte.',
            $notice->body,
        );
    }

    #[Test]
    public function theNoticeOpensTheAccountUnderTheOriginOfTheIssuer(): void
    {
        // When
        $notice = $this->notices()->of($this->alice, $this->enrolled());

        // Then
        static::assertSame('https://id.acme.example/account', $notice->accountPage);
    }

    private function notices(): CredentialChangeNotices
    {
        return CatalogueNotices::create();
    }

    private function enrolled(): CredentialChange
    {
        return new CredentialChange($this->alice, CredentialEnrolled::NAME, self::moment(), 'passkey');
    }

    private function written(string $locale): string
    {
        return new Moments(new UserTimeZone())->write(self::moment(), $this->alice, $locale);
    }

    private static function moment(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-11-22T14:05:00+00:00');
    }
}
