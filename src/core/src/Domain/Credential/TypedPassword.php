<?php

declare(strict_types=1);

namespace Beffroi\Core\Domain\Credential;

use Beffroi\Core\Domain\Precis\OpaqueString;
use Beffroi\Core\Exception\OpaqueStringRefusedException;
use Closure;
use SensitiveParameter;

/**
 * A password typed where one is verified (RFC 8265 §4.2.3, §8.2): its enforced form, and, while a hash computed before
 * the provider enforced the profile can be the one verified, the bytes as they were typed when they differ.
 */
final readonly class TypedPassword
{
    /**
     * @param list<string> $forms
     */
    private function __construct(
        #[SensitiveParameter]
        public string $enforced,
        #[SensitiveParameter]
        private array $forms,
    ) {
    }

    /**
     * @return self|null null when OpaqueString refuses what was typed, which is then no password and verifies against
     *                   no hash
     */
    public static function of(#[SensitiveParameter] string $typed): ?self
    {
        $enforced = self::enforced($typed);

        return $enforced === null ? null : new self($enforced, [$enforced]);
    }

    /**
     * The bytes as typed are a second form, which only a hash computed over them before the profile was enforced holds.
     *
     * @return self|null null when OpaqueString refuses what was typed
     */
    public static function orAsTyped(#[SensitiveParameter] string $typed): ?self
    {
        $enforced = self::enforced($typed);
        if ($enforced === null) {
            return null;
        }

        return new self($enforced, $enforced === $typed ? [$enforced] : [$enforced, $typed]);
    }

    /**
     * @return list<string> the enforced form, then the bytes as typed when they are a form of their own
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
     */
    public function verifiedBy(Closure $verifies): bool
    {
        return array_any($this->forms, fn ($form) => $verifies($form));
    }

    private static function enforced(#[SensitiveParameter] string $typed): ?string
    {
        try {
            return OpaqueString::enforce($typed);
        } catch (OpaqueStringRefusedException) {
            return null;
        }
    }
}
