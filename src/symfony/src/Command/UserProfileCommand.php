<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use function array_filter;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use function trim;

/**
 * The standard claims of OIDC Core §5.1 of a user (architecture §5.5), the whole of them every time: what
 * the command does not say is cleared, and a run that says nothing writes nothing rather than clearing
 * everything. Writes and prints what it wrote; reading a user is beffroi:user:show.
 *
 * What the source of the user holds is not the command's (decision 0002): a claim that upstream provider
 * holds stays what it wrote when the command does not say it, and saying it otherwise is refused, naming
 * the provider, without writing anything.
 */
#[AsCommand(
    name: 'beffroi:user:profile',
    description: 'Describe a user with the standard claims of OIDC Core section 5.1; what is not said is cleared, except what the upstream provider that created the user holds, which is kept, and saying that otherwise is refused; a run that says nothing writes nothing. To read a user, see beffroi:user:show.',
)]
final readonly class UserProfileCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private UserProvisioner $provisioner,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user.')]
        string $username,
        #[Option(description: 'Full name ("name").')]
        ?string $name = null,
        #[Option(description: 'Given name or first name ("given_name").')]
        ?string $givenName = null,
        #[Option(description: 'Surname or last name ("family_name").')]
        ?string $familyName = null,
        #[Option(description: 'Middle name ("middle_name").')]
        ?string $middleName = null,
        #[Option(description: 'Casual name ("nickname").')]
        ?string $nickname = null,
        #[Option(description: 'Shorthand name the user wishes to be referred to by ("preferred_username").')]
        ?string $preferredUsername = null,
        #[Option(description: 'URL of the profile page of the user ("profile"; "--profile" is an option of the console itself).')]
        ?string $profileUrl = null,
        #[Option(description: 'URL of the profile picture of the user ("picture").')]
        ?string $picture = null,
        #[Option(description: 'URL of the web page or blog of the user ("website").')]
        ?string $website = null,
        #[Option(description: 'Gender, "female", "male" or another value ("gender").')]
        ?string $gender = null,
        #[Option(description: 'Birthday, "YYYY-MM-DD" or "YYYY", "0000" for a year the user withholds ("birthdate").')]
        ?string $birthdate = null,
        #[Option(description: 'Time zone of the user, an IANA name such as "Europe/Paris" ("zoneinfo").')]
        ?string $zoneinfo = null,
        #[Option(description: 'Locale of the user, a BCP 47 tag such as "fr-FR" ("locale").')]
        ?string $locale = null,
        #[Option(description: 'Telephone number, E.164 recommended ("phone_number").')]
        ?string $phoneNumber = null,
        #[Option(description: 'The phone number was verified by whoever provisions the user ("phone_number_verified").')]
        bool $phoneNumberVerified = false,
        #[Option(description: 'Full mailing address, lines separated by "\n" ("address.formatted").')]
        ?string $address = null,
        #[Option(description: 'Street address component, lines separated by "\n" ("address.street_address").')]
        ?string $streetAddress = null,
        #[Option(description: 'City or locality ("address.locality").')]
        ?string $locality = null,
        #[Option(description: 'State, province, prefecture or region ("address.region").')]
        ?string $region = null,
        #[Option(description: 'Zip code or postal code ("address.postal_code").')]
        ?string $postalCode = null,
        #[Option(description: 'Country name ("address.country").')]
        ?string $country = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        $said = array_filter(
            [
                $name,
                $givenName,
                $familyName,
                $middleName,
                $nickname,
                $preferredUsername,
                $profileUrl,
                $picture,
                $website,
                $gender,
                $birthdate,
                $zoneinfo,
                $locale,
                $phoneNumber,
                $address,
                $streetAddress,
                $locality,
                $region,
                $postalCode,
                $country,
            ],
            static fn (?string $value): bool => self::given($value) !== null,
        );
        if ($said === [] && ! $phoneNumberVerified) {
            $io->error([
                'Nothing was said: this command writes the whole profile and clears what it is not told.',
                'To read a user, run "beffroi:user:show"; to clear the profile, say at least one claim.',
            ]);

            return Command::INVALID;
        }

        try {
            $this->provisioner->setProfile(
                $user,
                new Profile(
                    self::given($name),
                    self::given($givenName),
                    self::given($familyName),
                    self::given($middleName),
                    self::given($nickname),
                    self::given($preferredUsername),
                    self::given($profileUrl),
                    self::given($picture),
                    self::given($website),
                    self::given($gender),
                    self::given($birthdate),
                    self::given($zoneinfo),
                    self::given($locale),
                ),
                self::given($phoneNumber),
                $phoneNumberVerified,
                new Address(
                    self::given($address),
                    self::given($streetAddress),
                    self::given($locality),
                    self::given($region),
                    self::given($postalCode),
                    self::given($country),
                ),
            );
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        }

        $io->definitionList([
            'Username' => $user->username,
        ], ...UserShowCommand::claims($user));
        $io->success(sprintf('The user "%s" is described.', $user->username));

        return Command::SUCCESS;
    }

    /**
     * Empty says nothing.
     */
    private static function given(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
