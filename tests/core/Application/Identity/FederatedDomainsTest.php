<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0029, spec/saml.md S-60 to S-63: the domains of a tenant federated to an upstream provider, where the
 * login page sends an address of one, and whom no local credential signs in.
 */
final class FederatedDomainsTest extends TestCase
{
    private const string ACME = 'https://idp.acme.example/saml';

    private const string INITECH = 'https://idp.initech.example/saml';

    private Tenant $tenant;

    private FederatedDomains $federated;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $providers = new InMemoryUpstreamProviders();
        $providers->declare($this->tenant, new UpstreamProvider(self::ACME, [new EmailDomain('acme.example')]));
        $providers->declare($this->tenant, new UpstreamProvider(self::INITECH, [new EmailDomain('initech.example')]));
        $this->federated = new FederatedDomains($providers);
    }

    /**
     * S-61: the login page asks for an address first when the tenant declares an upstream provider.
     */
    #[Test]
    public function aTenantThatDeclaresAnUpstreamProviderFederates(): void
    {
        // When / Then
        static::assertTrue($this->federated->federates($this->tenant));
    }

    /**
     * S-61: a tenant that declares none shows the usual login page.
     */
    #[Test]
    public function aTenantThatDeclaresNoUpstreamProviderFederatesNothing(): void
    {
        // When / Then
        static::assertFalse($this->federated->federates(Fixtures::tenant('other')));
    }

    /**
     * S-61: an address is sent to the one provider of its domain, and nowhere when no provider answers for it; a
     * value without an "@" is a username, of no domain.
     */
    #[Test]
    #[DataProvider('provideIdentifiers')]
    public function anAddressIsFederatedToTheProviderOfItsDomain(string $identifier, ?string $provider): void
    {
        // When / Then
        static::assertSame($provider, $this->federated->providerOf($this->tenant, $identifier)?->name);
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function provideIdentifiers(): iterable
    {
        yield 'of the domain of a provider' => ['alice@acme.example', self::ACME];
        yield 'of the domain of another provider' => ['bob@initech.example', self::INITECH];
        yield 'of a domain nobody federates' => ['carol@umbrella.example', null];
        yield 'a username' => ['alice', null];
    }

    /**
     * S-61, S-44: an address whose domain the rule does not read is refused, and never taken for an address of a
     * domain nobody federates.
     */
    #[Test]
    public function anAddressWhoseDomainTheRuleDoesNotReadIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The domain of an address is no name of the DNS of two labels at least.');

        // When
        $this->federated->providerOf($this->tenant, 'alice@localhost');
    }

    /**
     * S-63: a person whose mailbox or username is of a federated domain is admitted no local credential, nor one an
     * address of whom the rule does not read on a tenant that federates; anybody else is.
     */
    #[Test]
    #[DataProvider('providePersons')]
    public function aLocalCredentialIsAdmittedForAPersonOfNoFederatedDomainOnly(string $username, ?string $email, bool $admitted): void
    {
        // Given
        $user = Fixtures::user($this->tenant, $username);
        if ($email !== null) {
            $user->changeEmail(new EmailAddress($email), false, Fixtures::now());
        }

        // When / Then
        static::assertSame($admitted, $this->federated->admitsLocalCredentials($user));
    }

    /**
     * @return iterable<string, array{string, string|null, bool}>
     */
    public static function providePersons(): iterable
    {
        yield 'a username and no mailbox' => ['alice', null, true];
        yield 'a mailbox of a domain nobody federates' => ['alice', 'alice@umbrella.example', true];
        yield 'a mailbox of a federated domain, not verified' => ['alice', 'alice@acme.example', false];
        yield 'a username of a federated domain' => ['alice@initech.example', null, false];
        yield 'a username of a domain nobody federates' => ['alice@umbrella.example', null, true];
        yield 'a username whose domain the rule does not read' => ['alice@localhost', null, false];
    }

    /**
     * S-63: a tenant that federates nothing admits every local credential, whatever the addresses of a person.
     */
    #[Test]
    public function aTenantThatFederatesNothingAdmitsEveryLocalCredential(): void
    {
        // Given
        $user = Fixtures::user(Fixtures::tenant('other'), 'alice@localhost');

        // When / Then
        static::assertTrue($this->federated->admitsLocalCredentials($user));
    }
}
