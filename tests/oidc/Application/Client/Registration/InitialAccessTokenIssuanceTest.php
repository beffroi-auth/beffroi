<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use function array_key_first;
use function array_map;
use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;
use Beffroi\Oidc\Tests\Fixture\Administrations;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenIssuance;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenIssued;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const PHP_INT_MAX;
use function sort;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7591 §1.2, Decision 0009, Decision 0038, Decision 0043
 */
final class InitialAccessTokenIssuanceTest extends TestCase
{
    private const string NOW = '2026-09-29T10:00:00+00:00';

    private InMemoryInitialAccessTokenRepository $tokens;

    private InitialAccessTokenIssuance $issuance;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->issuance = new InitialAccessTokenIssuance(
            Secrets::drawer(),
            $this->tokens,
            new MockClock(self::NOW),
            Registrations::reader(),
            new ConfigurationAdministrationResource('acme', Administrations::RESOURCE),
            $this->events,
        );
    }

    #[Test]
    public function issuingIsAnActOfTheTenantThatNamesTheHostWhenItsConsoleDidIt(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, 30, Fixtures::context());

        // Then
        static::assertEquals(
            [[$issued->token->id->toRfc4122(), new TheHost()]],
            array_map(
                static fn (InitialAccessTokenIssued $act): array => [$act->tokenId->toRfc4122(), $act->author()],
                $this->events->of(InitialAccessTokenIssued::class),
            ),
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function issuingThroughTheAdministrationNamesTheAdministrator(): void
    {
        // When
        $this->issuance->issueByAnAdministrator(
            Fixtures::tenant(),
            'The terminal of another administrator',
            1,
            1,
            new Subject('administrator-subject'),
            Fixtures::context(),
            administration: true,
        );

        // Then
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $this->events->of(InitialAccessTokenIssued::class)[0]->author());
    }

    #[Test]
    public function theValueIsOneThisProviderDrew(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, 30, Fixtures::context());

        // Then
        static::assertTrue(DrawnSecret::isValue($issued->value));
    }

    #[Test]
    public function theRowKeepsTheDigestAndNotTheValue(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, 30, Fixtures::context());

        // Then
        static::assertSame(DrawnSecret::digestOf($issued->value), $issued->token->digest);
    }

    #[Test]
    public function itIsWorthWhatWasAskedForForAsLongAsWasAskedFor(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 5, 7, Fixtures::context());

        // Then
        static::assertSame(5, $issued->token->registrationsAllowed);
        static::assertSame(self::NOW, $issued->token->issuedAt->format('c'));
        static::assertSame('2026-10-06T10:00:00+00:00', $issued->token->expiresAt->format('c'));
    }

    #[Test]
    public function theTokenIsFoundByTheTenantItWasIssuedFor(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When
        $issued = $this->issuance->issue($tenant, 'The team that integrates', 1, 30, Fixtures::context());

        // Then
        static::assertSame($issued->token, $this->tokens->findByDigest($tenant, DrawnSecret::digestOf($issued->value)));
    }

    #[Test]
    public function aTokenWorthNoRegistrationIsNotIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token is worth at least one registration; a token worth none is a token not issued.');

        // When
        $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 0, 30, Fixtures::context());
    }

    #[Test]
    public function aTokenWorthNoDayIsNotIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token is worth something for a day at least.');

        // When
        $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, 0, Fixtures::context());
    }

    /**
     * RFC 3339 §5.6
     */
    #[Test]
    #[DataProvider('provideDaysNoDateHolds')]
    public function aTokenThatWouldOutliveTheYear9999IsNotIssued(int $days): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token expires within the year 9999 at the latest, the last a date of RFC 3339 writes (section 5.6).');

        // When
        $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, $days, Fixtures::context());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideDaysNoDateHolds(): iterable
    {
        yield 'more days than four digits of a year count' => [3_000_000];
        yield 'more days than an interval holds' => [PHP_INT_MAX];
    }

    /**
     * Decision 0043
     */
    #[Test]
    public function theTokenKeepsWhatItGivesTheClientsItRegisters(): void
    {
        // Given
        $granted = new GrantedMembers([
            'resources' => ['https://api.example/invoices'],
            'access_token_format' => 'opaque',
        ]);

        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, 30, Fixtures::context(), $granted);

        // Then
        static::assertSame($granted, $issued->token->granted);
    }

    #[Test]
    public function aTokenIssuedToGiveNothingGivesNothing(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, 30, Fixtures::context());

        // Then
        static::assertNull($issued->token->granted);
    }

    /**
     * Decision 0043
     *
     * @param array<string, mixed> $granted
     */
    #[Test]
    #[DataProvider('provideGiftsThisProviderCannotServe')]
    public function aTokenThatWouldGiveWhatThisProviderCannotServeIsNotIssued(array $granted, string $message): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->issuance->issue(Fixtures::tenant(), 'invoices', 1, 30, Fixtures::context(), new GrantedMembers($granted));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideGiftsThisProviderCannotServe(): iterable
    {
        yield 'resources that are no list' => [
            ['resources' => 'https://api.example/invoices'],
            'The resources option of the client "invoices" must be a list of strings.',
        ];

        yield 'a shape of access token this provider does not issue' => [
            ['access_token_format' => 'invented'],
            'The access_token_format option of the client "invoices" must be one of: jwt, opaque.',
        ];

        yield 'a binding that is no boolean' => [
            ['require_sender_constrained_tokens' => 'yes'],
            'The require_sender_constrained_tokens option of the client "invoices" must be a boolean.',
        ];

        yield 'a type of token this provider does not read' => [
            ['token_exchange' => ['subject_token_types' => ['urn:example:params:oauth:token-type:invented']]],
            'The client "invoices" may present a "urn:example:params:oauth:token-type:invented", which this provider does not read; the wired token types are urn:ietf:params:oauth:token-type:access_token (RFC 8693 section 3).',
        ];

        yield 'an actor that is no subject' => [
            ['may_act' => ''],
            'The may_act option of the client "invoices" names a subject (OIDC Core section 2).',
        ];
    }

    #[Test]
    public function everyMemberATokenGivesIsReadBeforeItIsIssued(): void
    {
        // Given
        $given = GrantedMembers::NAMES;
        sort($given);

        // When
        $read = array_map(
            static fn (array $case): ?string => array_key_first($case[0]),
            iterator_to_array(self::provideGiftsThisProviderCannotServe(), false),
        );
        sort($read);

        // Then
        static::assertSame($given, $read);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aTokenThatWouldGiveAResourceWithAFragmentIsNotIssued(): void
    {
        // Given
        $granted = new GrantedMembers([
            'resources' => ['https://api.example/invoices#all'],
        ]);

        // When
        try {
            $this->issuance->issue(Fixtures::tenant(), 'invoices', 1, 30, Fixtures::context(), $granted);
        } catch (InvalidClientMetadataException) {
        }

        // Then
        static::assertSame([], [...$this->tokens->issuedIn(Fixtures::tenant())]);
    }

    #[Test]
    public function aTokenWithNoNameIsNotIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token carries the name the tenant gave it (RFC 7591 section 1.2).');

        // When
        $this->issuance->issue(Fixtures::tenant(), '', 1, 30, Fixtures::context());
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aTokenIsIssuedForTheAdministrationOfATenantThatNamesItsApi(): void
    {
        // When
        $issued = $this->issuance->issue(
            Fixtures::tenant(),
            'The terminal of the administrators',
            1,
            1,
            Fixtures::context(),
            administration: true,
        );

        // Then
        static::assertTrue($issued->token->administration);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function noTokenIsIssuedForTheAdministrationOfATenantThatNamesNoApi(): void
    {
        // Given
        $issuance = new InitialAccessTokenIssuance(
            Secrets::drawer(),
            $this->tokens,
            new MockClock(self::NOW),
            Registrations::reader(),
            new ConfigurationAdministrationResource('acme'),
            $this->events,
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The tenant "acme" names no administration API (BEFFROI_TENANT_ADMINISTRATION_RESOURCE): a token for its administration would register clients of nothing.');

        // When
        $issuance->issue(Fixtures::tenant(), 'The terminal of the administrators', 1, 1, Fixtures::context(), administration: true);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aTokenForTheAdministrationGivesNoResource(): void
    {
        // Given
        $granted = new GrantedMembers([
            'resources' => ['https://api.example/invoices'],
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token "The terminal of the administrators" is issued for the administration of the tenant, whose clients are given its administration API and no other resource (decision 0038).');

        // When
        $this->issuance->issue(Fixtures::tenant(), 'The terminal of the administrators', 1, 1, Fixtures::context(), $granted, true);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function aTokenForTheAdministrationGivesWhatIsNoResource(): void
    {
        // Given
        $granted = new GrantedMembers([
            'require_sender_constrained_tokens' => true,
        ]);

        // When
        $issued = $this->issuance->issue(
            Fixtures::tenant(),
            'The terminal of the administrators',
            1,
            1,
            Fixtures::context(),
            $granted,
            true,
        );

        // Then
        static::assertSame($granted, $issued->token->granted);
    }

    /**
     * Decision 0038
     *
     * @param list<string> $resources
     */
    #[Test]
    #[DataProvider('provideResourcesThatNameTheAdministrationApi')]
    public function aTokenThatWouldGiveTheAdministrationApiAmongItsResourcesIsNotIssued(array $resources): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token "invoices" names the administration API of the tenant among its resources, which only a token issued for the administration gives, to clients that authenticate with a key (decision 0038).');

        // When
        $this->issuance->issue(Fixtures::tenant(), 'invoices', 1, 30, Fixtures::context(), new GrantedMembers([
            'resources' => $resources,
        ]));
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function provideResourcesThatNameTheAdministrationApi(): iterable
    {
        yield 'the administration API alone' => [[Administrations::RESOURCE]];

        yield 'the administration API beside another' => [['https://api.example/invoices', Administrations::RESOURCE]];
    }
}
