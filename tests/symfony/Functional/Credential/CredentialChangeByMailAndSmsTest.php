<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Credential;

use function array_map;
use function array_values;
use App\Message\TellUserOfCredentialChange;
use App\Messenger\NotificationRetryPolicy;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use App\Messenger\RetrySchedule;
use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialChangeNotTold;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\Claim\PhoneNumber;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Closure;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Mailer\EventListener\MessageLoggerListener;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Stamp\DelayStamp;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Notifier\EventListener\NotificationLoggerListener;
use Symfony\Component\Notifier\Message\MessageInterface;

/**
 * Decision 0048, Decision 0049, NIST SP 800-63B-4 §4.6, Architecture §5.6
 */
final class CredentialChangeByMailAndSmsTest extends ConsoleTestCase
{
    private const string ADDRESS = 'alice@op.test';

    private const string NUMBER = '+33600000000';

    private const string ANOTHER_NUMBER = '+33699999999';

    /**
     * Nothing listens there: every mail is refused at the connection, as by a server that is down.
     */
    private const string UNREACHABLE_MAIL_DSN = 'smtp://127.0.0.1:1';

    /**
     * A bridge the application installs, whose provider answers 503 to every text (configureContainer()).
     */
    private const string UNAVAILABLE_SMS_DSN = 'sweego://key@default?region=FR&campaign_type=transac&shorten_urls=false';

    private const array VARIABLES = ['BEFFROI_TEST_MAIL_DSN', 'BEFFROI_TEST_SMS_DSN'];

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $container->set(
                'http_client',
                new MockHttpClient(
                    static fn (): MockResponse => new MockResponse('', [
                        'http_code' => 503,
                    ]),
                ),
            );
        };
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function eachChannelHasANoticeOfItsOwnOnTheLaneAfterWebPush(): void
    {
        // When
        self::tell(self::alice(verified: true));

        // Then
        static::assertSame(
            ['web_push', 'mail', 'sms'],
            array_map(static fn (Envelope $envelope): string => self::notice($envelope)->channel, self::queued()),
        );
    }

    #[Test]
    public function aChangeIsWrittenToTheAddressThePersonVerified(): void
    {
        // Given
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        $mails = self::mails();
        static::assertCount(1, $mails);
        static::assertSame([self::ADDRESS], array_map(static fn (Address $address): string => $address->getAddress(), $mails[0]->getTo()));
    }

    #[Test]
    public function aChangeIsTextedToTheNumberThePersonVerified(): void
    {
        // Given
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertSame([self::NUMBER], array_map(static fn (MessageInterface $text): ?string => $text->getRecipientId(), self::texts()));
    }

    #[Test]
    public function anAddressAndANumberNobodyVerifiedAreSentNothing(): void
    {
        // Given
        self::tell(self::alice(verified: false));

        // When
        self::work();

        // Then
        static::assertSame([[], []], [self::mails(), self::texts()]);
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aMailThatIsNeverTakenLeavesTheTextToTellThePerson(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_DSN'] = self::UNREACHABLE_MAIL_DSN;
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertCount(1, self::texts());
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aMailThatIsNotTakenIsWrittenAgainAsOftenAsTheScheduleOfTheNoticesAllows(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_DSN'] = self::UNREACHABLE_MAIL_DSN;
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertCount(self::notices()->attempts(), self::mails());
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aMailThatIsNeverTakenIsAnActOfThePersonOnceTheScheduleIsSpent(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_DSN'] = self::UNREACHABLE_MAIL_DSN;
        $alice = self::alice(verified: true);
        self::tell($alice);

        // When
        self::work();

        // Then
        static::assertCount(1, self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf($alice, [CredentialChangeNotTold::NAME], 10));
    }

    #[Test]
    public function aNoticeThatReachesThePersonIsNoAct(): void
    {
        // Given
        $alice = self::alice(verified: true);
        self::tell($alice);

        // When
        self::work();

        // Then
        static::assertSame([], self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf($alice, [CredentialChangeNotTold::NAME], 10));
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aTextThatIsNotTakenDoesNotWriteTheMailAgain(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SMS_DSN'] = self::UNAVAILABLE_SMS_DSN;
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertCount(1, self::mails());
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3, CNIL délibération n° 2022-100 point 55, BSI TR-03161-2 O.Auth_16
     */
    #[Test]
    public function aNumberTheOperatorChangesIsTextedToTheNumberItReplaced(): void
    {
        // Given
        self::alice(verified: true);
        self::console('beffroi:user:profile', ['username' => 'alice', '--phone-number' => self::ANOTHER_NUMBER]);

        // When
        self::work();

        // Then
        static::assertSame([self::NUMBER], array_map(static fn (MessageInterface $text): ?string => $text->getRecipientId(), self::texts()));
    }

    /**
     * Decision 0049, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function aNumberTheOperatorChangesIsWrittenToTheAddressOfThePerson(): void
    {
        // Given
        self::alice(verified: true);
        self::console('beffroi:user:profile', ['username' => 'alice', '--phone-number' => self::ANOTHER_NUMBER]);

        // When
        self::work();

        // Then
        static::assertSame([self::ADDRESS], array_map(static fn (Email $mail): string => $mail->getTo()[0]->getAddress(), self::mails()));
    }

    /**
     * Decision 0049, NIST SP 800-63A-4 §5.3, CNIL délibération n° 2022-100 point 55
     */
    #[Test]
    public function aNumberThePersonChangesIsTextedToTheNumberItReplaced(): void
    {
        // Given
        self::describedByThePerson(self::alice(verified: true), self::ANOTHER_NUMBER);

        // When
        self::work();

        // Then
        static::assertSame([self::NUMBER], array_map(static fn (MessageInterface $text): ?string => $text->getRecipientId(), self::texts()));
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theTextToTheReplacedNumberCarriesNeitherNumber(): void
    {
        // Given
        self::alice(verified: true);
        self::console('beffroi:user:profile', ['username' => 'alice', '--phone-number' => self::ANOTHER_NUMBER]);

        // When
        self::work();

        // Then
        $text = self::texts()[0]->getSubject();
        static::assertStringNotContainsString(self::NUMBER, $text);
        static::assertStringNotContainsString(self::ANOTHER_NUMBER, $text);
    }

    /**
     * Decision 0048, decision 0049
     */
    #[Test]
    public function aNumberNobodyVerifiedIsTextedNothingOnceReplaced(): void
    {
        // Given
        self::alice(verified: false);
        self::console('beffroi:user:profile', ['username' => 'alice', '--phone-number' => self::ANOTHER_NUMBER]);

        // When
        self::work();

        // Then
        static::assertSame([], self::texts());
    }

    /**
     * Decision 0049
     */
    #[Test]
    public function theSecondChangeOfANumberInAWindowWaitsForItsEndAndTheThirdQueuesNothing(): void
    {
        // Given
        self::alice(verified: true);

        // When
        foreach (['+33600000001', '+33600000002', '+33600000003'] as $number) {
            self::console('beffroi:user:profile', ['username' => 'alice', '--phone-number' => $number]);
        }

        // Then
        static::assertSame(
            [
                ['web_push',        false],
                ['mail',            false],
                ['sms',             false],
                ['replaced_number', false],
                ['web_push',        true],
                ['mail',            true],
                ['sms',             true],
            ],
            array_map(
                static fn (Envelope $envelope): array => [self::notice($envelope)->channel, $envelope->last(DelayStamp::class) !== null],
                self::queued(),
            ),
        );
    }

    /**
     * Decision 0049, NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aTextThatNeverReachesTheReplacedNumberIsAnActOfThePerson(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SMS_DSN'] = self::UNAVAILABLE_SMS_DSN;
        $alice = self::alice(verified: true);
        self::console('beffroi:user:profile', ['username' => 'alice', '--phone-number' => self::ANOTHER_NUMBER]);

        // When
        self::work();

        // Then
        static::assertCount(1, self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf($alice, [CredentialChangeNotTold::NAME], 10));
    }

    private static function alice(bool $verified): User
    {
        $alice = self::user();
        $alice->changeEmail(new EmailAddress(self::ADDRESS), $verified, self::now());
        $alice->changePhoneNumber(self::NUMBER, $verified, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);

        return $alice;
    }

    /**
     * Through the use case the profile page calls, the tenant opening the number to the person for that call alone: the
     * worker serves a tenant only as its configuration describes it.
     */
    private static function describedByThePerson(User $user, string $number): void
    {
        $tenant = $user->tenant;
        $opened = $tenant->selfServedClaims;
        $tenant->adoptSelfServedClaims(new SelfServedClaims(['phone_number']));
        self::service('test.beffroi.self_description', SelfDescription::class)
            ->describe($user, new PhoneNumber(), $number, RequestContext::unknown(self::now()));
        $tenant->adoptSelfServedClaims($opened);
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);
    }

    private static function tell(User $user): void
    {
        self::service('test.beffroi.credential_change_notifier', CredentialChangeNotifierInterface::class)
            ->tell(
                new CredentialChange($user, CredentialEnrolled::NAME, self::now(), 'passkey'),
            );
    }

    /**
     * The worker of the lane, under the mocked clock, for as long as its policy keeps a message coming back.
     */
    private static function work(): void
    {
        self::mockTime();
        self::console('messenger:consume', [
            'receivers' => ['async_notifications'],
            '--time-limit' => (string) (2 * self::notices()->waiting()),
            '--no-reset' => null,
        ]);
    }

    private static function notice(Envelope $envelope): TellUserOfCredentialChange
    {
        $message = $envelope->getMessage();
        static::assertInstanceOf(TellUserOfCredentialChange::class, $message);

        return $message;
    }

    private static function notices(): RetrySchedule
    {
        return self::service(NotificationRetryPolicy::class, NotificationRetryPolicy::class)->notices;
    }

    /**
     * Each mail handed to the transport, taken or not.
     *
     * @return list<Email>
     */
    private static function mails(): array
    {
        $mails = [];
        foreach (self::service('test.beffroi.mails', MessageLoggerListener::class)->getEvents()->getMessages() as $mail) {
            static::assertInstanceOf(Email::class, $mail);
            $mails[] = $mail;
        }

        return $mails;
    }

    /**
     * Each text handed to the transport, taken or not.
     *
     * @return list<MessageInterface>
     */
    private static function texts(): array
    {
        return array_values(self::service('test.beffroi.texts', NotificationLoggerListener::class)->getEvents()->getMessages());
    }
}
