<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use function array_keys;
use function array_map;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Scope\Scope;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class StandardClaimsProviderTest extends TestCase
{
    private StandardClaimsProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new StandardClaimsProvider();
    }

    /**
     * OIDC Core §5.4: "profile" stands for the fourteen claims of §5.1 about the person, "updated_at"
     * included, as a number of seconds; nothing of the other scopes leaks in.
     */
    #[Test]
    public function theProfileScopeGivesTheProfileClaims(): void
    {
        // When
        $claims = $this->provider->claims(self::fullUser(), self::scopes(['profile']), []);

        // Then
        static::assertSame(
            [
                'name' => 'Alice Martin',
                'given_name' => 'Alice',
                'family_name' => 'Martin',
                'middle_name' => 'Jeanne',
                'nickname' => 'ali',
                'preferred_username' => 'alice',
                'profile' => 'https://social.example/alice',
                'picture' => 'https://social.example/alice.png',
                'website' => 'https://alice.example',
                'gender' => 'female',
                'birthdate' => '1990-04-12',
                'zoneinfo' => 'Europe/Paris',
                'locale' => 'fr-FR',
                'updated_at' => Fixtures::now()->modify('+1 day')->getTimestamp(),
            ],
            $claims,
        );
    }

    /**
     * OIDC Core §5.4 "email", "address", "phone"; §5.1.1: the address is an object with the members
     * that have a value.
     */
    #[Test]
    public function theEmailAddressAndPhoneScopesGiveTheirClaims(): void
    {
        // When
        $claims = $this->provider->claims(self::fullUser(), self::scopes(['email', 'address', 'phone']), []);

        // Then
        static::assertSame(
            [
                'email' => 'alice@acme.example',
                'email_verified' => true,
                'phone_number' => '+33612345678',
                'phone_number_verified' => false,
                'address' => [
                    'formatted' => "1 rue de la Paix\n75002 Paris",
                    'street_address' => '1 rue de la Paix',
                    'locality' => 'Paris',
                    'postal_code' => '75002',
                    'country' => 'FR',
                ],
            ],
            $claims,
        );
    }

    /**
     * OIDC Core §5.1: "email_verified" and "phone_number_verified" are JSON booleans, true or false,
     * never strings (architecture §9).
     */
    #[Test]
    public function theVerificationFlagsAreJsonBooleans(): void
    {
        // Given
        $claims = $this->provider->claims(self::fullUser(), self::scopes(['email', 'address', 'phone']), []);

        // When
        $json = json_encode($claims, JSON_THROW_ON_ERROR);

        // Then
        static::assertSame(
            '{"email":"alice@acme.example","email_verified":true,"phone_number":"+33612345678","phone_number_verified":false,"address":{"formatted":"1 rue de la Paix\n75002 Paris","street_address":"1 rue de la Paix","locality":"Paris","postal_code":"75002","country":"FR"}}',
            $json,
        );
    }

    /**
     * OIDC Core §5.3.2: a claim the user has no value for is left out. A bare user with every scope
     * gives "updated_at" alone.
     */
    #[Test]
    public function absentAttributesGiveNoClaim(): void
    {
        // When
        $claims = $this->provider->claims(Fixtures::user(), self::scopes(['profile', 'email', 'address', 'phone']), []);

        // Then
        static::assertSame(
            [
                'updated_at' => Fixtures::now()->getTimestamp(),
            ],
            $claims,
        );
    }

    /**
     * OIDC Core §5.3.2: the verification flag goes with the value it qualifies, and an empty address is
     * no address.
     */
    #[Test]
    public function theVerificationFlagGoesWithTheValueItQualifies(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());
        $user->changeAddress(new Address(), Fixtures::now());

        // When
        $claims = $this->provider->claims($user, self::scopes(['email', 'address']), []);

        // Then
        static::assertSame(
            [
                'email' => 'alice@acme.example',
                'email_verified' => false,
            ],
            $claims,
        );
    }

    /**
     * OIDC Discovery §3 "scopes_supported": the provider announces the four scopes of OIDC Core §5.4.
     */
    #[Test]
    public function itAnnouncesTheScopesItServes(): void
    {
        // When
        $scopes = $this->provider->supportedScopes();

        // Then
        static::assertSame(['profile', 'email', 'address', 'phone'], array_map(static fn (Scope $scope): string => $scope->value, $scopes));
    }

    /**
     * OIDC Discovery §3 "claims_supported": the nineteen claims of §5.1 the scopes stand for, "sub"
     * being the resolver's.
     */
    #[Test]
    public function itAnnouncesTheClaimsItServes(): void
    {
        // When
        $claims = $this->provider->supportedClaims();

        // Then
        static::assertSame(
            [
                'name',
                'family_name',
                'given_name',
                'middle_name',
                'nickname',
                'preferred_username',
                'profile',
                'picture',
                'website',
                'gender',
                'birthdate',
                'zoneinfo',
                'locale',
                'updated_at',
                'email',
                'email_verified',
                'address',
                'phone_number',
                'phone_number_verified',
            ],
            $claims,
        );
        static::assertNotContains('sub', $claims);
    }

    /**
     * Every announced claim is one a full user actually gets, and nothing else.
     */
    #[Test]
    public function aFullUserGetsEveryAnnouncedClaimAndNothingElse(): void
    {
        // When
        $served = array_keys($this->provider->claims(self::fullUser(), new Scopes($this->provider->supportedScopes()), []));

        // Then
        static::assertEqualsCanonicalizing($this->provider->supportedClaims(), $served);
    }

    /**
     * OIDC Core §5.4: "openid" asks for no claim of its own ("sub" is the resolver's), and a scope
     * outside the four of §5.4 asks for none either.
     *
     * @param list<string> $scopes
     */
    #[Test]
    #[DataProvider('provideScopesWithoutClaims')]
    public function otherScopesGiveNothing(array $scopes): void
    {
        // When
        $claims = $this->provider->claims(self::fullUser(), self::scopes($scopes), []);

        // Then
        static::assertSame([], $claims);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function provideScopesWithoutClaims(): iterable
    {
        yield 'openid, offline_access and a custom scope' => [['openid', 'offline_access', 'api:read']];
    }

    /**
     * OIDC Core §5.5: a claim asked for by name is served without its scope; "essential", "value" and
     * "values" (§5.5.1) change nothing to what is served; a name the provider does not know gives
     * nothing. Requested and scope claims come out once each, in the order of §5.1.
     */
    #[Test]
    public function claimsRequestedByNameAreServedWithoutTheirScope(): void
    {
        // When
        $claims = $this->provider->claims(self::fullUser(), self::scopes(['email']), [
            'email_verified' => new ClaimRequest(true, false),
            'given_name' => new ClaimRequest(),
            'phone_number' => new ClaimRequest(false, null, ['+33600000000']),
            'groups' => new ClaimRequest(true),
        ]);

        // Then
        static::assertSame(['given_name', 'email', 'email_verified', 'phone_number'], array_keys($claims));
        static::assertSame('Alice', $claims['given_name']);
        static::assertTrue($claims['email_verified']);
        static::assertSame('+33612345678', $claims['phone_number']);
    }

    /**
     * @param list<string> $values
     */
    private static function scopes(array $values): Scopes
    {
        return new Scopes(array_map(static fn (string $value): Scope => new Scope($value), $values));
    }

    private static function fullUser(): User
    {
        return new User(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice',
            new EmailAddress('alice@acme.example'),
            true,
            new Profile(
                'Alice Martin',
                'Alice',
                'Martin',
                'Jeanne',
                'ali',
                'alice',
                'https://social.example/alice',
                'https://social.example/alice.png',
                'https://alice.example',
                'female',
                '1990-04-12',
                'Europe/Paris',
                'fr-FR',
            ),
            '+33612345678',
            false,
            new Address("1 rue de la Paix\n75002 Paris", '1 rue de la Paix', 'Paris', null, '75002', 'FR'),
            Fixtures::now(),
            Fixtures::now()->modify('+1 day'),
            UserSource::local(),
        );
    }
}
