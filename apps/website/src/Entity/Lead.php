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

    /** The last time the visitor agreed to the emails: the retention period runs from it. */
    #[ORM\Column]
    public private(set) DateTimeImmutable $consentedAt;

    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $confirmationSentAt = null;

    /** What Sweego reported of the confirmation, the last time it reported each: accepted by the mailbox. */
    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $confirmationDeliveredAt = null;

    /** Opened, as far as the pixel of Sweego can tell: a mail client that loads no image opens nothing. */
    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $confirmationOpenedAt = null;

    /** A link of it followed. */
    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $confirmationClickedAt = null;

    /** Refused by the mailbox, for a while or for good. */
    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $confirmationBouncedAt = null;

    /** Reported as spam by the visitor. */
    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $markedAsSpamAt = null;

    /** Unsubscribed by the visitor, from the link their mail client shows. */
    #[ORM\Column(nullable: true)]
    public private(set) ?DateTimeImmutable $unsubscribedAt = null;

    #[ORM\Column(length: 32, enumType: LeadStatus::class)]
    public LeadStatus $status = LeadStatus::New;

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    public ?string $notes = null;

    public function __construct(
        #[ORM\Column(length: 180)]
        public private(set) string $email,
        string $firstName,
        string $lastName,
        ?string $company,
        OidcProvider $provider,
        ?string $providerOther,
        string $source,
        #[ORM\Column]
        public private(set) DateTimeImmutable $createdAt,
    ) {
        $this->id = Uuid::v7();
        $this->describe($firstName, $lastName, $company, $provider, $providerOther, $source, $this->createdAt);
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

    public function confirmationDelivered(DateTimeImmutable $at): void
    {
        $this->confirmationDeliveredAt = $at;
    }

    public function confirmationOpened(DateTimeImmutable $at): void
    {
        $this->confirmationOpenedAt = $at;
    }

    public function confirmationClicked(DateTimeImmutable $at): void
    {
        $this->confirmationClickedAt = $at;
    }

    public function confirmationBounced(DateTimeImmutable $at): void
    {
        $this->confirmationBouncedAt = $at;
    }

    public function markedAsSpam(DateTimeImmutable $at): void
    {
        $this->markedAsSpamAt = $at;
    }

    public function unsubscribed(DateTimeImmutable $at): void
    {
        $this->unsubscribedAt = $at;
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
