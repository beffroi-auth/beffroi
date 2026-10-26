<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\ProfileChapter;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function array_keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the record itself, in the archive a person asks for. The names are those of OIDC Core §5.1,
 * which is what RGPD article 20 means by a commonly used format: a person who takes this file to another
 * provider hands it a document that provider already reads.
 */
final class ProfileChapterTest extends TestCase
{
    #[Test]
    public function theChapterNamesTheClaimsOfTheSpecification(): void
    {
        // When
        $lines = new ProfileChapter()->of(Fixtures::user());

        // Then
        static::assertSame(
            [
                'sub',
                'username',
                'name',
                'given_name',
                'family_name',
                'middle_name',
                'nickname',
                'preferred_username',
                'profile',
                'picture',
                'website',
                'email',
                'email_verified',
                'gender',
                'birthdate',
                'zoneinfo',
                'locale',
                'phone_number',
                'phone_number_verified',
                'address',
                'created_at',
                'updated_at',
                'disabled_at',
                'source',
            ],
            array_keys($lines[0]),
        );
    }

    /**
     * A claim this deployment offers on no page is a claim this provider holds all the same, and article
     * 15 asks for what is held: the chapter reads the record and not what is wired.
     */
    #[Test]
    public function theChapterHoldsWhatThePersonSaidOfThemselves(): void
    {
        // Given
        $user = Fixtures::user();
        $user->updateProfile(new Profile(name: 'Augusta Ada King-Noel', nickname: 'Ada', locale: 'en-GB'), Fixtures::now());

        // When
        $lines = new ProfileChapter()->of($user);

        // Then
        static::assertSame('Augusta Ada King-Noel', $lines[0]['name']);
        static::assertSame('Ada', $lines[0]['nickname']);
        static::assertSame('en-GB', $lines[0]['locale']);
    }

    /**
     * OIDC Core §5.1.1: the address member by member, as the userinfo endpoint serves it.
     */
    #[Test]
    public function theAddressIsWrittenMemberByMember(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeAddress(new Address(streetAddress: '12 Grand Rue', postalCode: '67000', locality: 'Strasbourg', country: 'FR'), Fixtures::now());

        // When
        $lines = new ProfileChapter()->of($user);

        // Then
        static::assertSame(
            [
                'formatted' => null,
                'street_address' => '12 Grand Rue',
                'locality' => 'Strasbourg',
                'region' => null,
                'postal_code' => '67000',
                'country' => 'FR',
            ],
            $lines[0]['address'],
        );
    }

    #[Test]
    public function anAddressThisProviderHoldsNoneOfIsNone(): void
    {
        // When
        $lines = new ProfileChapter()->of(Fixtures::user());

        // Then
        static::assertNull($lines[0]['address']);
    }

    /**
     * An attribute that is absent carries no verification flag either, as OIDC Core §5.1 has it: a flag
     * on nothing would say something was not verified where there is nothing to verify.
     */
    #[Test]
    public function anAbsentAttributeCarriesNoVerification(): void
    {
        // When
        $lines = new ProfileChapter()->of(Fixtures::user());

        // Then
        static::assertNull($lines[0]['email']);
        static::assertNull($lines[0]['email_verified']);
        static::assertNull($lines[0]['phone_number']);
        static::assertNull($lines[0]['phone_number_verified']);
    }

    #[Test]
    public function aVerifiedAddressSaysSo(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('ada@example.org'), true, Fixtures::now());

        // When
        $lines = new ProfileChapter()->of($user);

        // Then
        static::assertSame('ada@example.org', $lines[0]['email']);
        static::assertTrue($lines[0]['email_verified']);
    }

    /**
     * The chapter that holds exactly one record answers a list of one, because a chapter that is sometimes
     * an object and sometimes a list is a document a reader has to know in advance.
     */
    #[Test]
    public function theChapterIsAListOfOne(): void
    {
        // When / Then
        static::assertCount(1, new ProfileChapter()->of(Fixtures::user()));
    }

    /**
     * Decision 0002: the source that created the record is held of that person, sealed as a personal datum,
     * so article 15 asks for it: the provider and what it holds.
     */
    #[Test]
    public function theProviderThatCreatedTheRecordIsNamedWithWhatItHolds(): void
    {
        // Given
        $user = User::create(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('ada-subject'),
            'ada',
            Fixtures::now(),
            source: UserSource::upstream('https://idp.acme.example/saml', ['email', 'family_name']),
        );

        // When
        $lines = new ProfileChapter()->of($user);

        // Then
        static::assertSame(
            [
                'provider' => 'https://idp.acme.example/saml',
                'claims' => ['email', 'family_name'],
            ],
            $lines[0]['source'],
        );
    }

    #[Test]
    public function aRecordNoProviderCreatedNamesNone(): void
    {
        // When
        $lines = new ProfileChapter()->of(Fixtures::user());

        // Then
        static::assertSame(
            [
                'provider' => null,
                'claims' => [],
            ],
            $lines[0]['source'],
        );
    }

    #[Test]
    public function anAccountThatWasDisabledSaysWhen(): void
    {
        // Given
        $user = Fixtures::user();
        $user->disable(Fixtures::now());

        // When
        $lines = new ProfileChapter()->of($user);

        // Then
        static::assertSame(Fixtures::now()->format('c'), $lines[0]['disabled_at']);
    }
}
