<?php

declare(strict_types=1);

namespace App\Credential;

use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * The channels a change is told through, each found again by its name, and those that tell a change to the channel it
 * replaced, apart.
 */
final readonly class CredentialChangeChannels
{
    /**
     * @var list<string>
     */
    private array $names;

    /**
     * @var array<string, list<string>> by the claim of the channel they reach once replaced
     */
    private array $replacing;

    /**
     * @var array<string, CredentialChangeChannelInterface>
     */
    private array $channels;

    /**
     * @param iterable<CredentialChangeChannelInterface> $channels in the order a change is told through them
     *
     * @throws InvalidConfigurationException when two channels go by the same name
     */
    public function __construct(iterable $channels)
    {
        $names = [];
        $replacing = [];
        $named = [];
        foreach ($channels as $channel) {
            $name = $channel->name();
            if (isset($named[$name])) {
                throw new InvalidConfigurationException(sprintf(
                    'Two channels that tell a person of a change to their credentials go by the name "%s": a notice for that name would reach the first one alone.',
                    $name,
                ));
            }
            if ($channel instanceof ReplacedChannelInterface) {
                $replacing[$channel->claim()][] = $name;
            } else {
                $names[] = $name;
            }
            $named[$name] = $channel;
        }
        $this->names = $names;
        $this->replacing = $replacing;
        $this->channels = $named;
    }

    /**
     * @return list<string> in the order a change is told through them
     */
    public function names(): array
    {
        return $this->names;
    }

    /**
     * @param string $claim the claim of a channel a change replaced, OIDC Core §5.1
     *
     * @return list<string> the names of the channels that tell the change to it, in the order they were given
     */
    public function reaching(string $claim): array
    {
        return $this->replacing[$claim] ?? [];
    }

    public function named(string $name): ?CredentialChangeChannelInterface
    {
        return $this->channels[$name] ?? null;
    }
}
