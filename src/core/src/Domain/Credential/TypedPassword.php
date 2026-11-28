<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Credential;

use Beffroi\Core\Domain\Precis\OpaqueString;
use Beffroi\Core\Exception\PasswordRefusedException;
use Closure;
use SensitiveParameter;

/**
 * A password typed where one is verified (RFC 8265 §4.2.3, §8.2): its enforced form, and the bytes as they were typed
 * when they differ, which only a hash computed over them before the profile was enforced holds.
 */
final readonly class TypedPassword
{
    public string $enforced;

    /**
     * @var list<string>
     */
    private array $forms;

    /**
     * @throws PasswordRefusedException
     */
    private function __construct(#[SensitiveParameter] string $typed)
    {
        $this->enforced = OpaqueString::enforce($typed);
        $this->forms = $typed === $this->enforced ? [$typed] : [$this->enforced, $typed];
    }

    /**
     * @return self|null null when OpaqueString refuses what was typed, which is then no password and verifies against
     *                   no hash
     */
    public static function of(#[SensitiveParameter] string $typed): ?self
    {
        try {
            return new self($typed);
        } catch (PasswordRefusedException) {
            return null;
        }
    }

    /**
     * @return list<string> the enforced form, then the bytes as typed when they differ
     */
    public function forms(): array
    {
        return $this->forms;
    }

    /**
     * Each form in turn, whatever the hash, until one verifies: the bytes as typed never verify a hash of an enforced
     * form, and a refusal then costs as many verifications whichever form a hash was computed over.
     *
     * @param Closure(string): bool $verifies
     *
     * @return string|null the form that verified
     */
    public function verifiedBy(Closure $verifies): ?string
    {
        foreach ($this->forms as $form) {
            if ($verifies($form)) {
                return $form;
            }
        }

        return null;
    }
}
