<?php

declare(strict_types=1);

namespace App\Credential;

/**
 * NIST SP 800-63B-4 §4.6
 */
final readonly class CredentialChangeNotice
{
    /**
     * @param string $accountPage where the person reads the change, a page that acts on nothing
     */
    public function __construct(
        public string $title,
        public string $subject,
        public string $body,
        public string $accountPage,
    ) {
    }

    public function mailText(): string
    {
        return $this->body . "\n\n" . $this->accountPage . "\n";
    }

    public function text(): string
    {
        return $this->title . "\n" . $this->body . "\n" . $this->accountPage;
    }
}
