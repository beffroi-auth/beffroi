<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;
use Beffroi\Oidc\Tests\Fixture\Administrations;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenIssuance;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenRevocation;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Beffroi\Oidc\Domain\Client\Registration\IssuedInitialAccessToken;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenRevoked;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use function array_map;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2, Decision 0009
 */
final class InitialAccessTokenRevocationTest extends TestCase
{
    private const string ISSUED_AT = '2026-09-29T10:00:00+00:00';

    private const string REVOKED_AT = '2026-09-30T11:00:00+00:00';

    private InMemoryInitialAccessTokenRepository $tokens;

    private MockClock $clock;

    private Tenant $tenant;

    private RecordingEventDispatcher $events;

    private RequestContext $context;

    protected function setUp(): void
    {
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->clock = new MockClock(self::ISSUED_AT);
        $this->tenant = Fixtures::tenant();
        $this->events = new RecordingEventDispatcher();
        $this->context = Fixtures::context();
    }

    #[Test]
    public function aTokenTheTenantTakesBackAuthorisesNothing(): void
    {
        // Given
        $issued = $this->issue();
        $this->clock->modify(self::REVOKED_AT);

        // When
        $this->revocation()->revoke($this->tenant, $issued->token->id, $this->context);

        // Then
        static::assertFalse($issued->token->authorisesARegistration($this->clock->now()));
    }

    #[Test]
    public function revokingItIsAnActOfTheTenantThatNamesTheHostWhenItsConsoleDidIt(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->revocation()->revoke($this->tenant, $issued->token->id, $this->context);

        // Then
        static::assertEquals(
            [[$issued->token->id->toRfc4122(), new TheHost()]],
            array_map(
                static fn (InitialAccessTokenRevoked $act): array => [$act->tokenId->toRfc4122(), $act->author()],
                $this->events->of(InitialAccessTokenRevoked::class),
            ),
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function revokingItThroughTheAdministrationNamesTheAdministrator(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $this->revocation()->revokeByAnAdministrator($this->tenant, $issued->token->id, new Subject('administrator-subject'), $this->context);

        // Then
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $this->events->of(InitialAccessTokenRevoked::class)[0]->author());
    }

    #[Test]
    public function revokingItAgainWritesNoSecondAct(): void
    {
        // Given
        $issued = $this->issue();
        $revocation = $this->revocation();
        $revocation->revoke($this->tenant, $issued->token->id, $this->context);

        // When
        $revocation->revoke($this->tenant, $issued->token->id, $this->context);

        // Then
        static::assertCount(1, $this->events->of(InitialAccessTokenRevoked::class));
    }

    #[Test]
    public function revokingItTwiceKeepsTheInstantItWasFirstTakenBack(): void
    {
        // Given
        $issued = $this->issue();
        $this->clock->modify(self::REVOKED_AT);
        $revocation = $this->revocation();
        $revocation->revoke($this->tenant, $issued->token->id, $this->context);

        // When
        $this->clock->modify('2026-10-01T12:00:00+00:00');
        $token = $revocation->revoke($this->tenant, $issued->token->id, $this->context);

        // Then
        static::assertSame(self::REVOKED_AT, $token?->revokedAt?->format('c'));
    }

    #[Test]
    public function aTokenOfAnotherTenantIsNotTakenBack(): void
    {
        // Given
        $issued = $this->issue();

        // When
        $token = $this->revocation()->revoke(Fixtures::tenant('other', 'https://id.other.example'), $issued->token->id, $this->context);

        // Then
        static::assertNull($token);
    }

    #[Test]
    public function anIdentifierNoTokenCarriesNamesNothing(): void
    {
        // Given
        $this->issue();

        // When
        $token = $this->revocation()->revoke($this->tenant, Uuid::v7(), $this->context);

        // Then
        static::assertNull($token);
    }

    #[Test]
    public function whatItAlreadyRegisteredIsLeftAlone(): void
    {
        // Given
        $issued = $this->issue(3);
        $this->tokens->spend($issued->token, $this->clock->now());
        $this->clock->modify(self::REVOKED_AT);

        // When
        $token = $this->revocation()->revoke($this->tenant, $issued->token->id, $this->context);

        // Then
        static::assertSame(1, $token?->registrationsServed);
    }

    private function issue(int $registrationsAllowed = 1): IssuedInitialAccessToken
    {
        return new InitialAccessTokenIssuance(
            Secrets::drawer(),
            $this->tokens,
            $this->clock,
            Registrations::reader(),
            new ConfigurationAdministrationResource('acme', Administrations::RESOURCE),
            new RecordingEventDispatcher(),
        )->issue(
            $this->tenant,
            'The team that integrates',
            $registrationsAllowed,
            30,
            $this->context,
        );
    }

    private function revocation(): InitialAccessTokenRevocation
    {
        return new InitialAccessTokenRevocation($this->tokens, $this->tokens, $this->clock, $this->events);
    }
}
