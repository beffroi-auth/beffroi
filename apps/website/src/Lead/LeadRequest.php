<?php

declare(strict_types=1);

namespace App\Lead;

use Symfony\Component\Validator\Constraints as Assert;

/**
 * What the sign-up form submits. Every property is nullable: the form writes what it receives before validation runs.
 */
final class LeadRequest
{
    #[Assert\NotBlank(message: 'Please enter your first name.')]
    #[Assert\Length(max: 100)]
    public ?string $firstName = null;

    #[Assert\NotBlank(message: 'Please enter your last name.')]
    #[Assert\Length(max: 100)]
    public ?string $lastName = null;

    #[Assert\Length(max: 150)]
    public ?string $company = null;

    #[Assert\NotBlank(message: 'Please enter your email address.')]
    #[Assert\Email(message: 'Please enter a valid email address.', mode: Assert\Email::VALIDATION_MODE_HTML5)]
    #[Assert\Length(max: 180)]
    public ?string $email = null;

    #[Assert\NotNull(message: 'Please choose the provider you use, or "None".')]
    public ?OidcProvider $provider = null;

    #[Assert\Length(max: 100)]
    public ?string $providerOther = null;

    #[Assert\IsTrue(message: 'Please agree to receive these emails, or we cannot let you know.')]
    public bool $consent = false;
}
