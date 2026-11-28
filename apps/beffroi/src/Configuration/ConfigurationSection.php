<?php

declare(strict_types=1);

namespace App\Configuration;

use App\Http\ByteLimit;
use App\Http\Timeout;
use Beffroi\Core\Domain\Listing\RetentionWindow;
use DateInterval;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_string;
use function sprintf;
use Symfony\Component\Config\Definition\Builder\BooleanNodeDefinition;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_closure;

/**
 * A value may still be an environment placeholder, resolved only at runtime: a section never casts it.
 */
abstract readonly class ConfigurationSection implements ConfigurationSectionInterface
{
    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    protected function own(array $config): array
    {
        return self::section($config, $this->name());
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    protected static function section(array $config, string $key): array
    {
        $section = $config[$key] ?? null;

        return is_array($section) ? $section : [];
    }

    /**
     * @param array<array-key, mixed> $section
     */
    protected static function string(array $section, string $key): string
    {
        $value = $section[$key] ?? null;
        if (! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a string.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return int|string a number, or the environment placeholder that stands for it until runtime
     */
    protected static function integer(array $section, string $key): int|string
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     *
     * @return bool|string a flag, or the environment placeholder the container resolves into one
     */
    protected static function boolean(array $section, string $key): bool|string
    {
        $value = $section[$key] ?? null;
        if (! is_bool($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be true or false.', $key));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $section
     */
    protected static function bounded(array $section, string $key, ?int $maximum = null, ?string $named = null, int $minimum = 1): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of seconds.', $named ?? $key));
        }

        return inline_service(DateInterval::class)->factory(BoundedNumber::interval(...))->args([$value, $named ?? $key, $maximum, $minimum]);
    }

    /**
     * @param array<array-key, mixed> $section
     */
    protected static function timeout(array $section, string $key, string $named): object
    {
        $value = $section[$key] ?? null;
        if (! is_float($value) && ! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of seconds.', $named));
        }

        return inline_service(Timeout::class)->factory(BoundedNumber::timeout(...))->args([is_int($value) ? (float) $value : $value, $named]);
    }

    /**
     * @param array<array-key, mixed> $section
     */
    protected static function bytes(array $section, string $key, string $named): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of bytes.', $named));
        }

        return inline_service(ByteLimit::class)->factory(BoundedNumber::bytes(...))->args([$value, $named]);
    }

    /**
     * @param array<array-key, mixed> $section
     */
    protected static function days(array $section, string $key): object
    {
        $value = $section[$key] ?? null;
        if (! is_int($value) && ! is_string($value)) {
            throw new InvalidConfigurationException(sprintf('The "beffroi" configuration key "%s" must be a number of days.', $key));
        }

        return inline_service(RetentionWindow::class)->args([$value]);
    }

    /**
     * Stands for canBeEnabled(), whose placeholder symfony/config 8.2 resolves when the container is compiled: an image
     * would keep the role the environment of its build named.
     *
     * @return BooleanNodeDefinition<null>
     */
    protected static function enabled(): BooleanNodeDefinition
    {
        $enabled = new BooleanNodeDefinition('enabled');
        $enabled->defaultFalse();

        return $enabled;
    }

    /**
     * The service of a role, built only while the role is on, and null while it is off.
     *
     * @param class-string $class
     */
    protected static function servedBy(ServicesConfigurator $services, string $class, string $service, string $role): void
    {
        $services
            ->set($class)
            ->factory([service($role), 'served'])
            ->args([service_closure($service)]);
    }
}
