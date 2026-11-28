<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use App\Mail\PgpMailSigner;
use App\Messenger\NotificationNotDeliveredException;
use App\Mail\Smime;
use App\Mail\SmimeMailSigner;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\MailProtections;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use App\Tests\Symfony\Fixture\ScratchFiles;
use Beffroi\Core\Bridge\InMemory\InMemoryMailSigningKeyRepository;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\MailEncryptionKey;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ReplacedChannel;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use function openssl_pkcs7_decrypt;
use function openssl_pkcs7_verify;
use function openssl_x509_fingerprint;
use const PKCS7_DETACHED;
use const PKCS7_NOVERIFY;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Message;

/**
 * Decision 0051, RFC 8551 §3.7, RFC 3156 §6.1
 */
final class MailProtectionTest extends TestCase
{
    private const string NOW = '2026-11-22T10:00:00+00:00';

    private Tenant $tenant;

    private InMemoryMailSigningKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryMailSigningKeyRepository();
    }

    #[Test]
    public function aTenantThatHoldsNoKeyWritesTheMailAsItIs(): void
    {
        // Given
        $mail = self::mail();

        // When
        $protected = $this->protect($this->person(), $mail);

        // Then
        static::assertSame($mail, $protected);
    }

    #[Test]
    public function theCurrentKeySignsTheMail(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // When
        $protected = $this->protect($this->person(), self::mail());

        // Then
        static::assertSame('sender', self::signerOf($protected));
    }

    #[Test]
    public function theKeySetInPlaceOfAnotherSignsAndTheOneItReplacedNoLonger(): void
    {
        // Given
        $replaced = MailSigningKeys::smime($this->tenant, 'sender', new DateTimeImmutable('2026-11-01T10:00:00+00:00'));
        $replaced->replace(new DateTimeImmutable('2026-11-20T10:00:00+00:00'));
        $this->keys->save($replaced);
        $this->keys->save(MailSigningKeys::smime($this->tenant, 'sender-next', new DateTimeImmutable('2026-11-20T10:00:00+00:00')));

        // When
        $protected = $this->protect($this->person(), self::mail());

        // Then
        static::assertSame('sender-next', self::signerOf($protected));
    }

    #[Test]
    public function aKeyPastItsCertificateFailsTheMail(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('cannot sign this one: it is past its certificate, or it was set for another sender.');

        // When
        $this->protect($this->person(), self::mail(), '2126-06-01T00:00:00+00:00');
    }

    #[Test]
    public function aKeySetForAnotherSenderFailsTheMail(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('cannot sign this one: it is past its certificate, or it was set for another sender.');

        // When
        $this->protect($this->person(), self::mail(), sender: 'alerts@acme.example');
    }

    #[Test]
    public function withoutAKeyOfTheFormatOfThePersonTheFirstFormatWiredSigns(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $this->keys->save(MailSigningKeys::pgp($this->tenant));

        // When
        $protected = $this->protect($this->person(), self::mail());

        // Then
        static::assertStringContainsString('protocol="application/pkcs7-signature"', $protected->toString());
    }

    #[Test]
    public function theFormatOfTheKeyThePersonGaveSignsTheMailToThem(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $this->keys->save(MailSigningKeys::pgp($this->tenant));
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));
        $clock = new MockClock(self::NOW);

        // When
        $protected = MailProtections::over($this->keys, $clock, signers: [
            new PgpMailSigner($clock),
            new SmimeMailSigner(),
        ])->of($person, new EmailAddress(MailSigningKeys::SENDER), self::mail());

        // Then
        static::assertStringContainsString('protocol="application/pkcs7-signature"', self::decrypted($protected->toString()));
    }

    #[Test]
    public function aMailToAPersonWhoGaveACertificateIsSignedThenEncrypted(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));

        // When
        $protected = $this->protect($person, self::mail())->toString();

        // Then
        static::assertStringContainsString('application/pkcs7-mime', $protected);
        static::assertStringNotContainsString('Open your account to answer.', $protected);
        static::assertStringContainsString('multipart/signed', self::decrypted($protected));
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    public function theConfirmationOfAnAddressIsSignedAndEncryptedToNoOne(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));

        // When
        $protected = MailProtections::over($this->keys, new MockClock(self::NOW))
            ->ofAConfirmation($person, new EmailAddress(MailSigningKeys::SENDER), self::mail())
            ->toString();

        // Then
        static::assertStringContainsString('protocol="application/pkcs7-signature"', $protected);
        static::assertStringNotContainsString('application/pkcs7-mime', $protected);
        static::assertSame(
            'sender',
            self::signerOf(MailProtections::over($this->keys, new MockClock(self::NOW))->ofAConfirmation(
                $person,
                new EmailAddress(MailSigningKeys::SENDER),
                self::mail(),
            )),
        );
    }

    /**
     * NIST SP 800-63B-4 §4.2.1.2
     */
    #[Test]
    public function theConfirmationOfATenantThatSignsAndCannotSignItFails(): void
    {
        // Given
        $this->keys->save(MailSigningKeys::smime($this->tenant));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('cannot sign this one: it is past its certificate, or it was set for another sender.');

        // When
        MailProtections::over($this->keys, new MockClock(self::NOW))->ofAConfirmation(
            $this->person(),
            new EmailAddress('someone-else@acme.example'),
            self::mail(),
        );
    }

    #[Test]
    public function aMailToAPersonWhoseCertificateIsNoLongerValidFails(): void
    {
        // Given
        $person = $this->person();
        $person->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('certificate or key they gave is not valid now.');

        // When
        $this->protect($person, self::mail(), '2126-06-01T00:00:00+00:00');
    }

    #[Test]
    public function aMailToAPersonWhoseKeyNoWiredFormatWritesFails(): void
    {
        // Given
        $person = $this->person();
        $person->encryptMailTo(new MailEncryptionKey(
            'elsewhere',
            'material',
            'ABCD',
            [new EmailAddress('alice@acme.example')],
        ), new DateTimeImmutable(self::NOW));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIsOrContains('in the format elsewhere, which this deployment does not write.');

        // When
        $this->protect($person, self::mail());
    }

    /**
     * Decision 0049, decision 0051
     */
    #[Test]
    public function aMailToTheAddressAChangeReplacedIsEncryptedToWhatThePersonGaveForIt(): void
    {
        // Given
        $person = $this->person();
        $replaced = ReplacedChannel::address(new EmailAddress('alice@acme.example'), new Smime()->read(MailFixtures::read('person-certificate.pem')));
        $person->changeEmail(new EmailAddress('alice@elsewhere.example'), false, new DateTimeImmutable(self::NOW));

        // When
        $protected = MailProtections::over($this->keys, new MockClock(self::NOW))
            ->ofTheReplaced($person, $replaced, new EmailAddress(MailSigningKeys::SENDER), self::mail())
            ->toString();

        // Then
        static::assertStringContainsString('Open your account to answer.', self::decrypted($protected));
    }

    /**
     * Decision 0049, decision 0051
     */
    #[Test]
    public function aMailToTheAddressAChangeReplacedIsNeverEncryptedToWhatThePersonGaveForTheNextOne(): void
    {
        // Given
        $person = $this->person();
        $replaced = ReplacedChannel::address(new EmailAddress('alice@acme.example'), null);
        $person->changeEmail(new EmailAddress('alice@elsewhere.example'), true, new DateTimeImmutable(self::NOW));
        $person->encryptMailTo(new MailEncryptionKey(
            'elsewhere',
            'material',
            'ABCD',
            [new EmailAddress('alice@elsewhere.example')],
        ), new DateTimeImmutable(self::NOW));

        // When
        $protected = MailProtections::over($this->keys, new MockClock(self::NOW))
            ->ofTheReplaced($person, $replaced, new EmailAddress(MailSigningKeys::SENDER), self::mail())
            ->toString();

        // Then
        static::assertStringContainsString('Open your account to answer.', $protected);
    }

    private function protect(User $user, Email $mail, string $now = self::NOW, string $sender = MailSigningKeys::SENDER): Message
    {
        return MailProtections::over($this->keys, new MockClock($now))->of($user, new EmailAddress($sender), $mail);
    }

    private function person(): User
    {
        $user = Fixtures::user($this->tenant);
        $user->changeEmail(new EmailAddress('alice@acme.example'), true, new DateTimeImmutable(self::NOW));

        return $user;
    }

    private static function mail(): Email
    {
        return new Email()
            ->from(MailSigningKeys::SENDER)
            ->to('alice@acme.example')
            ->subject('A sign-in is waiting')
            ->text('Open your account to answer.');
    }

    /**
     * The name of the fixture whose certificate signed it.
     */
    private static function signerOf(Message $message): string
    {
        $files = new ScratchFiles();
        $signer = $files->holding();
        openssl_pkcs7_verify($files->holding($message->toString()), PKCS7_DETACHED | PKCS7_NOVERIFY, $signer);
        $certificate = ScratchFiles::read($signer);
        foreach (['sender', 'sender-next'] as $name) {
            if (openssl_x509_fingerprint($certificate, 'sha256') === openssl_x509_fingerprint(MailFixtures::read($name . '-certificate.pem'), 'sha256')) {
                return $name;
            }
        }

        return 'nobody';
    }

    private static function decrypted(string $message): string
    {
        $files = new ScratchFiles();
        $opened = $files->holding();
        openssl_pkcs7_decrypt($files->holding($message), $opened, MailFixtures::read('person-certificate.pem'), MailFixtures::read('person-key.pem'));

        return ScratchFiles::read($opened);
    }
}
