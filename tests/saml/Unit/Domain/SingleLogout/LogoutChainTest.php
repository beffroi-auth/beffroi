<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleLogout;

use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;

/**
 * spec/saml.md S-31, S-32, section 7: a chain open ten minutes from its last step, kept under the digest of its
 * reference and bound to the digest of the secret of a browser; a request of the provider valid five minutes.
 */
final class LogoutChainTest extends TestCase
{
    /**
     * S-32, section 7: a chain written now closes ten minutes later, open until the second before.
     */
    #[Test]
    public function aChainIsOpenTenMinutes(): void
    {
        // Given
        $chain = new LogoutChain(
            'digest',
            'secret',
            Fixtures::tenant(),
            null,
            new LogoutProgress([], [], null, false, null, null),
            LogoutChain::closesAt(Fixtures::now()),
        );

        // When / Then
        static::assertSame(
            [true, false],
            [$chain->isOpen(Fixtures::now()->modify('+599 seconds')), $chain->isOpen(Fixtures::now()->modify('+600 seconds'))],
        );
    }

    /**
     * S-32: what is kept of a reference is its SHA-256, in hexadecimal.
     */
    #[Test]
    public function aReferenceIsKeptAsItsDigest(): void
    {
        // When / Then
        static::assertSame('52367a6622b19f08825e915fad80c542ad4f4c34dbcebad9f5007994b3e39208', LogoutChain::digestOf('reference'));
    }

    /**
     * S-32: a chain is held by the secret whose digest it keeps, and by no other.
     */
    #[Test]
    #[DataProvider('provideSecrets')]
    public function aChainIsHeldByTheSecretWhoseDigestItKeeps(string $secret, bool $holds): void
    {
        // Given
        $chain = new LogoutChain(
            'digest',
            LogoutChain::digestOf('GJx3sTZ1n3W0pQm7e2Lr9VbY4kCq8HfA6dUoE5iNwXs'),
            Fixtures::tenant(),
            null,
            new LogoutProgress([], [], null, false, null, null),
            LogoutChain::closesAt(Fixtures::now()),
        );

        // When / Then
        static::assertSame($holds, $chain->isHeldBy(new LogoutChainSecret($secret)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideSecrets(): iterable
    {
        yield 'the secret of the browser that began it' => ['GJx3sTZ1n3W0pQm7e2Lr9VbY4kCq8HfA6dUoE5iNwXs', true];
        yield 'another secret' => ['GJx3sTZ1n3W0pQm7e2Lr9VbY4kCq8HfA6dUoE5iNwXt', false];
    }

    /**
     * S-32: the secret of a browser is 32 bytes of random_bytes(), in base64url without padding, and none drawn is
     * drawn twice.
     */
    #[Test]
    public function aSecretIsThirtyTwoBytesDrawnAtRandom(): void
    {
        // When
        $first = LogoutChainSecret::draw();
        $second = LogoutChainSecret::draw();

        // Then
        static::assertSame(
            [1, 1, false],
            [
                preg_match('/^[A-Za-z0-9_-]{43}$/D', $first->value),
                preg_match('/^[A-Za-z0-9_-]{43}$/D', $second->value),
                $first->value === $second->value,
            ],
        );
    }

    /**
     * S-32: what is kept of the secret of a browser is its SHA-256, in hexadecimal.
     */
    #[Test]
    public function aSecretIsKeptAsItsDigest(): void
    {
        // When / Then
        static::assertSame('52367a6622b19f08825e915fad80c542ad4f4c34dbcebad9f5007994b3e39208', new LogoutChainSecret('reference')->digest());
    }

    /**
     * S-32, decision 0011: a row names no person, two digests, its tenant, a request ID drawn at random, where the
     * chain stands and when it closes.
     */
    #[Test]
    public function aRowNamesNoPerson(): void
    {
        // When / Then
        static::assertEquals(
            [
                'reference' => new NoPersonalDatum(Reason::HASHED),
                'secret' => new NoPersonalDatum(Reason::HASHED),
                'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
                'awaitingRequest' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
                'progress' =>
                    new NoPersonalDatum('sessions by their identifiers drawn at random, service providers, which are applications, and where the chain ends: a URI a client registered with the state it drew, or the ID and the RelayState a service provider drew for its own request'),
                'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            ],
            LogoutChain::classifiedFields(),
        );
    }

    /**
     * S-31, section 7: the request the provider sends is valid five minutes from its IssueInstant.
     */
    #[Test]
    public function aNoticeIsValidFiveMinutes(): void
    {
        // When / Then
        static::assertEquals(
            Fixtures::now()->modify('+300 seconds'),
            new SignOutNotice('https://id.acme.example/saml/metadata', 'https://sp.example.org/saml', 'nameid', 'session', Fixtures::now())->notOnOrAfter(),
        );
    }
}
