<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusedException;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0029, spec/saml.md S-60: the three places that ask which provider a domain is federated to read it by
 * one rule, so that none of them takes an address for one of no federated domain while another sends it to its
 * provider: the discovery of the login page (FederatedDomains::providerOf()), the first sign-in through the provider
 * (JustInTimeProvisioning::personNamedBy()), and the refusal of a local credential
 * (FederatedDomains::admitsLocalCredentials()).
 *
 * The first sign-in is handed an EmailAddress, whose domain is in ASCII: an address in a U-label, or with a final
 * dot, is no address it is ever handed, the assertion consumer service writing the domain of an address a provider
 * asserts as its A-label before it is one (issue #784).
 */
final class OneDomainRuleTest extends TestCase
{
    private const string PROVIDER = 'https://idp.acme.example/saml';

    /**
     * The discovery refuses the address, whose domain the rule does not read.
     */
    private const string REFUSED = 'refused';

    /**
     * The first sign-in creates the person.
     */
    private const string CREATED = 'created';

    /**
     * The first sign-in refuses the person, of no domain the provider answers for.
     */
    private const string OUTSIDE = 'outside its domains';

    /**
     * The spelling is no EmailAddress, which the first sign-in is never handed.
     */
    private const string NO_ADDRESS = 'no address';

    private Tenant $tenant;

    private UpstreamProvider $provider;

    private FederatedDomains $federated;

    private JustInTimeProvisioning $provisioning;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->provider = new UpstreamProvider(self::PROVIDER, [new EmailDomain('acme.example'), new EmailDomain('xn--bcher-kva.example')]);
        $providers = new InMemoryUpstreamProviders();
        $providers->declare($this->tenant, $this->provider);
        $this->federated = new FederatedDomains($providers);
        $clock = new MockClock('2026-10-23T09:00:00+00:00');
        $users = new InMemoryUserRepository();
        $identities = new InMemoryLinkedIdentityRepository();
        $credentials = new InMemoryCredentialRepository();
        $this->provisioning = new JustInTimeProvisioning(
            $identities,
            $users,
            new UserProvisioner(
                $users,
                $credentials,
                new ActivePassword(new ActiveCredentials($credentials)),
                new NativePasswordHasher(),
                new BreachedPasswordRefusal(BreachedPasswordsOfARecord::holding([])),
                new EnrolmentRefusal($this->federated),
                new SymfonyUuidGenerator(),
                $clock,
            ),
            new IdentityLinker($identities, new SymfonyUuidGenerator(), $clock),
            new RecordingEventDispatcher(),
            $clock,
            new WritesAsTheyCome(),
            new SymfonyUuidGenerator(),
            new UpstreamMemberships(new InMemoryGroupMembershipRepository(), new InMemoryGroupMembershipRepository(), new SymfonyUuidGenerator(), $clock),
        );
    }

    /**
     * @param string|null $discovered the provider the login page sends the address to, none, or a refusal
     * @param string $provisioned what the first sign-in through the provider does with a person of that address
     * @param bool $admitted whether a local credential signs a person named by that address in
     */
    #[Test]
    #[DataProvider('provideSpellings')]
    public function theThreePlacesReadTheDomainOfAnAddressAlike(string $address, ?string $discovered, string $provisioned, bool $admitted): void
    {
        // Given
        $person = Fixtures::user($this->tenant, $address);

        // When
        $readings = [$this->discovered($address), $this->provisioned($address), $this->federated->admitsLocalCredentials($person)];

        // Then
        static::assertSame([$discovered, $provisioned, $admitted], $readings);
    }

    /**
     * @return iterable<string, array{string, string|null, string, bool}>
     */
    public static function provideSpellings(): iterable
    {
        yield 'its A-label' => ['alice@xn--bcher-kva.example', self::PROVIDER, self::CREATED, false];
        yield 'its A-label in capitals' => ['alice@XN--BCHER-KVA.example', self::PROVIDER, self::CREATED, false];
        yield 'a U-label' => ['alice@bücher.example', self::PROVIDER, self::NO_ADDRESS, false];
        yield 'a U-label in capitals' => ['alice@BÜCHER.example', self::PROVIDER, self::NO_ADDRESS, false];
        yield 'in capitals' => ['alice@ACME.Example', self::PROVIDER, self::CREATED, false];
        yield 'a subdomain it does not declare' => ['alice@eu.acme.example', null, self::OUTSIDE, true];
        yield 'a final dot' => ['alice@acme.example.', self::REFUSED, self::NO_ADDRESS, false];
    }

    private function discovered(string $address): ?string
    {
        try {
            return $this->federated->providerOf($this->tenant, $address)?->name;
        } catch (InvalidArgumentException) {
            return self::REFUSED;
        }
    }

    private function provisioned(string $address): string
    {
        try {
            $email = new EmailAddress($address);
        } catch (InvalidArgumentException) {
            return self::NO_ADDRESS;
        }
        try {
            $this->provisioning->personNamedBy($this->tenant, $this->provider, 'the-subject-of-alice', $email, [], Fixtures::context());
        } catch (UpstreamProvisioningRefusedException) {
            return self::OUTSIDE;
        }

        return self::CREATED;
    }
}
