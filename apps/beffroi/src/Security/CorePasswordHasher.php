<?php

declare(strict_types=1);

namespace App\Security;

use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Credential\TypedPassword;
use Beffroi\Core\Domain\Precis\OpaqueString;
use Beffroi\Core\Exception\ExceptionInterface;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Beffroi\Core\Port\PasswordHasherInterface as CoreHasher;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use SensitiveParameter;
use Symfony\Component\PasswordHasher\Exception\InvalidPasswordException;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

/**
 * What a component of Symfony hashes or verifies is the form OpaqueString enforces, as in the core (decision 0065): a
 * string the profile refuses is no password, which is never hashed and verifies against nothing.
 */
final readonly class CorePasswordHasher implements PasswordHasherInterface
{
    public function __construct(
        private CoreHasher $hasher,
        private PasswordAlgorithmsInterface $algorithms,
    ) {
    }

    public function hash(#[SensitiveParameter] string $plainPassword): string
    {
        try {
            return self::encode($this->hasher->hash(OpaqueString::enforce($plainPassword)));
        } catch (ExceptionInterface $exception) {
            throw new InvalidPasswordException($exception->getMessage(), 0, $exception);
        }
    }

    public function verify(string $hashedPassword, #[SensitiveParameter] string $plainPassword): bool
    {
        $hash = $this->decode($hashedPassword);
        if ($hash === null) {
            return false;
        }
        try {
            return (
                TypedPassword::orAsTyped($plainPassword)?->verifiedBy(fn (#[SensitiveParameter] string $form): bool => $this->hasher->verify($hash, $form))
                !== null
            );
        } catch (ExceptionInterface) {
            return false;
        }
    }

    public function needsRehash(string $hashedPassword): bool
    {
        $hash = $this->decode($hashedPassword);
        if ($hash === null) {
            return false;
        }
        try {
            return $this->hasher->needsRehash($hash);
        } catch (ExceptionInterface) {
            return false;
        }
    }

    public static function encode(PasswordHash $hash): string
    {
        return json_encode([
            'algorithm' => $hash->algorithm->name(),
            'encoded' => $hash->encoded,
            'parameters' => $hash->parameters,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * No algorithm is guessed: a name nothing wired accounts for reads as no hash at all.
     */
    public function decode(string $encoded): ?PasswordHash
    {
        try {
            $decoded = json_decode($encoded, true, 3, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
        if (! is_array($decoded)) {
            return null;
        }
        $named = $decoded['algorithm'] ?? null;
        $algorithm = is_string($named) ? $this->algorithm($named) : null;
        $hash = $decoded['encoded'] ?? null;
        $parameters = $decoded['parameters'] ?? [];
        if ($algorithm === null || ! is_string($hash) || $hash === '' || ! is_array($parameters)) {
            return null;
        }
        $validated = [];
        foreach ($parameters as $name => $value) {
            if (! is_string($name) || ! is_int($value) && ! is_string($value)) {
                return null;
            }
            $validated[$name] = $value;
        }

        return new PasswordHash($algorithm, $hash, $validated);
    }

    private function algorithm(string $name): ?PasswordAlgorithmInterface
    {
        try {
            return $this->algorithms->named($name);
        } catch (UnsupportedAlgorithmException) {
            return null;
        }
    }
}
