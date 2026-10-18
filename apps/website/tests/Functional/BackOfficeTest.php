<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Entity\Admin;
use App\Entity\Lead;
use App\Lead\LeadStatus;
use App\Lead\OidcProvider;
use App\Tests\DatabaseReset;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class BackOfficeTest extends WebTestCase
{
    use DatabaseReset;

    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        self::resetDatabase();
    }

    #[Test]
    public function itSendsAnonymousVisitorsToTheSignInPage(): void
    {
        // When
        $this->client->request('GET', '/admin/lead');

        // Then
        static::assertResponseRedirects('/admin/login');
    }

    #[Test]
    public function itListsTheLeadsToAnAdmin(): void
    {
        // Given
        $this->givenALead('ada@example.com');
        $this->client->loginUser($this->givenAnAdmin());

        // When
        $this->client->request('GET', '/admin/lead');

        // Then
        static::assertResponseIsSuccessful();
        static::assertAnySelectorTextContains('td', 'ada@example.com');
    }

    #[Test]
    public function itExportsTheLeadsAsCsv(): void
    {
        // Given
        $this->givenALead('ada@example.com');
        $this->client->loginUser($this->givenAnAdmin());

        // When
        $this->client->request('GET', '/admin/lead/export');

        // Then
        static::assertResponseHeaderSame('Content-Type', 'text/csv; charset=utf-8');
        $csv = (string) $this->client->getInternalResponse()->getContent();
        static::assertStringStartsWith("\u{FEFF}created_at,first_name,last_name,company,email,", $csv);
        static::assertStringContainsString(',Ada,Lovelace,,ada@example.com,"Microsoft Entra ID",', $csv);
    }

    #[Test]
    public function itSetsTheStatusAndTheNotesOfALead(): void
    {
        // Given
        $id = $this->givenALead('ada@example.com');
        $this->client->loginUser($this->givenAnAdmin());
        $crawler = $this->client->request('GET', '/admin/lead/'.$id.'/edit');
        $form = $crawler->filter('form[name="Lead"]')->form();

        // When
        $this->client->submit($form, [
            'Lead[status]' => LeadStatus::Interested->value,
            'Lead[notes]' => 'Runs Keycloak for 40 apps, wants the hosted offer.',
        ]);

        // Then
        self::entityManager()->clear();
        $lead = self::entityManager()->getRepository(Lead::class)->findOneBy(['email' => 'ada@example.com']);
        static::assertInstanceOf(Lead::class, $lead);
        static::assertSame(LeadStatus::Interested, $lead->status);
        static::assertSame('Runs Keycloak for 40 apps, wants the hosted offer.', $lead->notes);
    }

    #[Test]
    public function itDeletesALead(): void
    {
        // Given
        $id = $this->givenALead('ada@example.com');
        $this->client->loginUser($this->givenAnAdmin());
        $crawler = $this->client->request('GET', '/admin/lead');
        $token = $crawler->filter('#action-confirmation-form input[name="token"]')->attr('value');

        // When
        $this->client->request('POST', '/admin/lead/'.$id.'/delete', ['token' => $token]);

        // Then
        static::assertSame(0, self::entityManager()->getRepository(Lead::class)->count());
    }

    #[Test]
    public function itSignsAnAdminIn(): void
    {
        // Given
        $this->givenAnAdmin();
        $crawler = $this->client->request('GET', '/admin/login');

        // When
        $this->client->submit($crawler->selectButton('Sign in')->form([
            '_username' => 'admin@beffroi.tech',
            '_password' => 'a long enough password',
        ]), serverParameters: ['HTTP_SEC_FETCH_SITE' => 'same-origin']);

        // Then
        static::assertResponseRedirects('/admin');
    }

    private function givenAnAdmin(): Admin
    {
        $admin = new Admin('admin@beffroi.tech', '');
        $hasher = static::getContainer()->get(UserPasswordHasherInterface::class);
        $admin->changePassword($hasher->hashPassword($admin, 'a long enough password'));
        self::entityManager()->persist($admin);
        self::entityManager()->flush();

        return $admin;
    }

    private function givenALead(string $email): string
    {
        $lead = new Lead($email, 'Ada', 'Lovelace', null, OidcProvider::EntraId, null, 'test', new \DateTimeImmutable());
        self::entityManager()->persist($lead);
        self::entityManager()->flush();

        return $lead->id->toRfc4122();
    }
}
