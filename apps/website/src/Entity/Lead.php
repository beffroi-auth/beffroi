<?php

declare(strict_types=1);

namespace App\Entity;

use App\Lead\LeadStatus;
use App\Lead\OidcProvider;
use App\Repository\LeadRepository;
use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Somebody who asked to hear about the release. One row per email address: signing up again updates the row.
 * What the visitor gave is read only; the status and the notes are the back office's.
 */
#[ORM\Entity(repositoryClass: LeadRepository::class)]
#[ORM\Table(name: 'lead')]
#[ORM\UniqueConstraint(name: 'lead_email', columns: ['email'])]
class Lead
{
    #[ORM\Id]
    #[ORM\Column(type: UuidType::NAME)]
    public private(set) Uuid $id;

    #[ORM\Column(length: 180)]
    public private(set) string $email;

    #[ORM\Column(length: 100)]
    public private(set) string $firstName;

    #[ORM\Column(length: 100)]
    public private(set) string $lastName;

    #[ORM\Column(length: 150, nullable: true)]
    public private(set) ?string $company;

    #[ORM\Column(length: 32, enumType: OidcProvider::class)]
    public private(set) OidcProvider $provider;

    /** What the visitor typed when the provider is "Other", and only then. */
    #[ORM\Column(length: 100, nullable: true)]
    public private(set) ?string $providerOther;

    /** Where the sign-up came from, such as the event the page was made for. */
    #[ORM\Column(length: 64)]
    public private(set) string $source;

    #[ORM\Column]
    public private(set) DateTimeImmutable $createdAt;

    /** The last time the visitor agreed to the emails: the retention period runs from it. */
    #[ORM\Column]
    public private(set) DateTimeImmutable $consentedAt;

    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $confirmationSentAt = null;

    #[ORM\Column(length: 32, enumType: LeadStatus::class)]
    public LeadStatus $status = LeadStatus::New;

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    public ?string $notes = null;

    public function __construct(
        string $email,
        string $firstName,
        string $lastName,
        ?string $company,
        OidcProvider $provider,
        ?string $providerOther,
        string $source,
        DateTimeImmutable $now,
    ) {
        $this->id = Uuid::v7();
        $this->email = $email;
        $this->createdAt = $now;
        $this->describe($firstName, $lastName, $company, $provider, $providerOther, $source, $now);
    }

    /**
     * The same visitor signed up again: what they gave last wins, and their consent is renewed.
     */
    public function signedUpAgain(
        string $firstName,
        string $lastName,
        ?string $company,
        OidcProvider $provider,
        ?string $providerOther,
        string $source,
        DateTimeImmutable $now,
    ): void {
        $this->describe($firstName, $lastName, $company, $provider, $providerOther, $source, $now);
    }

    public function confirmationSent(DateTimeImmutable $at): void
    {
        $this->confirmationSentAt = $at;
    }

    private function describe(
        string $firstName,
        string $lastName,
        ?string $company,
        OidcProvider $provider,
        ?string $providerOther,
        string $source,
        DateTimeImmutable $now,
    ): void {
        $this->firstName = $firstName;
        $this->lastName = $lastName;
        $this->company = $company;
        $this->provider = $provider;
        $this->providerOther = OidcProvider::Other === $provider ? $providerOther : null;
        $this->source = $source;
        $this->consentedAt = $now;
    }
}
