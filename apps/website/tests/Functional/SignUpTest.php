<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Entity\Lead;
use App\Lead\OidcProvider;
use App\Tests\DatabaseReset;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;

final class SignUpTest extends WebTestCase
{
    use ClockSensitiveTrait;
    use DatabaseReset;

    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        // What a browser sends with a form submitted from the page itself (stateless CSRF protection).
        $this->client->setServerParameter('HTTP_SEC_FETCH_SITE', 'same-origin');
        self::resetDatabase();
    }

    #[Test]
    public function itShowsTheFormWithoutSettingACookie(): void
    {
        // When
        $this->client->request('GET', '/symfonycon');

        // Then
        static::assertResponseIsSuccessful();
        static::assertSelectorExists('form[name="signup"]');
        static::assertResponseNotHasHeader('Set-Cookie');
    }

    #[Test]
    public function itRecordsAValidSignUp(): void
    {
        // Given
        self::mockTime('2026-11-26 10:30:00');

        // When
        $this->signUp(['company' => 'Acme']);

        // Then
        $lead = $this->onlyLead();
        static::assertSame('lukasz@example.pl', $lead->email);
        static::assertSame('Łukasz', $lead->firstName);
        static::assertSame('Żółć', $lead->lastName);
        static::assertSame('Acme', $lead->company);
        static::assertSame(OidcProvider::Keycloak, $lead->provider);
        static::assertSame('symfonycon-warsaw-2026', $lead->source);
        static::assertSame('2026-11-26 10:30:00', $lead->consentedAt->format('Y-m-d H:i:s'));
    }

    #[Test]
    public function itRedirectsAValidSignUpToTheThankYouPage(): void
    {
        // When
        $this->signUp();

        // Then
        static::assertResponseRedirects('/symfonycon/thanks', 303);
    }

    #[Test]
    public function itConfirmsAValidSignUpByEmail(): void
    {
        // When
        $this->signUp();

        // Then
        static::assertEmailCount(1);
        $email = static::getMailerMessage();
        static::assertNotNull($email);
        static::assertEmailAddressContains($email, 'From', 'bonjour@beffroi.tech');
        static::assertEmailAddressContains($email, 'To', 'lukasz@example.pl');
        static::assertEmailTextBodyContains($email, 'Hello Łukasz,');
    }

    #[Test]
    public function itStoresTheEmailAddressInLowerCase(): void
    {
        // When
        $this->signUp(['email' => '  Lukasz@Example.PL ']);

        // Then
        static::assertSame('lukasz@example.pl', $this->onlyLead()->email);
    }

    #[Test]
    public function itAcceptsASignUpWithoutCompany(): void
    {
        // When
        $this->signUp(['company' => '']);

        // Then
        static::assertNull($this->onlyLead()->company);
    }

    #[Test]
    public function itKeepsTheNameOfAnotherProvider(): void
    {
        // When
        $this->signUp(['provider' => 'other', 'providerOther' => 'Gluu']);

        // Then
        static::assertSame('Gluu', $this->onlyLead()->providerOther);
    }

    #[Test]
    public function itDropsTheNameOfAnotherProviderWhenAListedOneIsChosen(): void
    {
        // When
        $this->signUp(['provider' => 'auth0', 'providerOther' => 'Gluu']);

        // Then
        static::assertNull($this->onlyLead()->providerOther);
    }

    /**
     * @param array<string, string> $fields
     */
    #[Test]
    #[DataProvider('provideIncompleteSignUps')]
    public function itRefusesAnIncompleteSignUp(array $fields, string $error): void
    {
        // When
        $this->signUp($fields);

        // Then
        static::assertResponseStatusCodeSame(422);
        static::assertSelectorTextContains($error, 'Please');
        static::assertSame(0, self::entityManager()->getRepository(Lead::class)->count());
    }

    /**
     * @return iterable<string, array{array<string, string|null>, string}>
     */
    public static function provideIncompleteSignUps(): iterable
    {
        yield 'no first name' => [['firstName' => ''], '#signup_firstName_error'];
        yield 'no last name' => [['lastName' => ''], '#signup_lastName_error'];
        yield 'no email' => [['email' => ''], '#signup_email_error'];
        yield 'an invalid email' => [['email' => 'lukasz@'], '#signup_email_error'];
        yield 'no provider' => [['provider' => ''], '#signup_provider_error'];
        yield 'no consent' => [['consent' => null], '#signup_consent_error'];
    }

    #[Test]
    public function itRefusesASignUpSentFromAnotherSite(): void
    {
        // Given
        $this->client->setServerParameter('HTTP_SEC_FETCH_SITE', 'cross-site');

        // When
        $this->signUp();

        // Then
        static::assertResponseStatusCodeSame(422);
        static::assertSame(0, self::entityManager()->getRepository(Lead::class)->count());
    }

    #[Test]
    public function itUpdatesTheLeadOfAnAddressThatSignedUpBefore(): void
    {
        // Given
        $this->signUp();

        // When
        $this->signUp(['firstName' => 'Łukasz Jan', 'provider' => 'okta']);

        // Then
        $lead = $this->onlyLead();
        static::assertSame('Łukasz Jan', $lead->firstName);
        static::assertSame(OidcProvider::Okta, $lead->provider);
    }

    /**
     * The emails a test sends are counted across its requests: two sign-ups, one confirmation.
     */
    #[Test]
    public function itSendsNoSecondConfirmationToAnAddressThatSignedUpBefore(): void
    {
        // Given
        $this->signUp();

        // When
        $this->signUp();

        // Then
        static::assertEmailCount(1);
    }

    /**
     * Submits the form of the page with a complete sign-up, changed by $fields (null unticks a box).
     *
     * @param array<string, string|null> $fields
     */
    private function signUp(array $fields = []): void
    {
        $crawler = $this->client->request('GET', '/symfonycon');
        $form = $crawler->selectButton('Notify me')->form();

        $values = array_merge([
            'firstName' => 'Łukasz',
            'lastName' => 'Żółć',
            'company' => '',
            'email' => 'lukasz@example.pl',
            'provider' => 'keycloak',
            'providerOther' => '',
            'consent' => '1',
        ], $fields);

        $submitted = [];
        foreach ($values as $name => $value) {
            // A checkbox ticks on true and unticks on false.
            $submitted['signup[' . $name . ']'] = 'consent' === $name ? null !== $value : $value;
        }

        $this->client->submit($form, $submitted);
    }

    private function onlyLead(): Lead
    {
        $leads = self::entityManager()->getRepository(Lead::class)->findAll();
        static::assertCount(1, $leads);

        return $leads[0];
    }
}
