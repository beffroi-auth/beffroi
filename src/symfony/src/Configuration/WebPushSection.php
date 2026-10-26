<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Ciba\WebPushApprovalChannel;
use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Push\WebPushSender;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Vapid;
use function is_string;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;

/**
 * Whether this deployment reaches its users through the push services of their own browsers (RFC 8030),
 * and what a push service is told to write to when something is wrong with what it is sent.
 *
 * A deployment that names no subject wires nothing: no channel reaches anybody by push, the tenant draws
 * no application server key, and the page where a browser would subscribe says so. That is the default,
 * because how a deployment reaches its users is the one thing about them it cannot be told in advance
 * (architecture §5.6), and a channel nobody asked for is a channel nobody wanted. The algorithm of that
 * key is left dormant then, so that a key drawn before the subject was taken away is read by nothing
 * until a subject is named again (DormantKeyAlgorithms).
 */
final readonly class WebPushSection extends ConfigurationSection
{
    /**
     * Seconds one push to one push service is given, connection included. Nobody is waiting on it, but a
     * push service that hangs must not hold a worker.
     */
    public const float DEFAULT_TIMEOUT = 3.0;

    /**
     * The tag the channel takes its place in the lane by, the same one a deployment tags a channel of its
     * own with.
     */
    public const string CHANNEL_TAG = 'beffroi.pending_approval_channel';

    /**
     * The tag an algorithm of a key the tenant hands out is wired by (§3.3).
     */
    public const string ALGORITHM_TAG = 'beffroi.application_server_algorithm';

    public function name(): string
    {
        return 'web_push';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('web_push')
            ->info('Reaching a user through the push service of a browser they signed in with (RFC 8030, architecture §5.6). Absent, nothing of it is wired: no push leaves this deployment and the page where a browser would subscribe says so.')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('subject')
            ->info('The "sub" of the token this provider signs for a push service (RFC 8292 §2.1): a "mailto:" or "https:" URI at which the operator of this deployment can be reached about what it sends. Naming one is what turns web push on; absent, nothing of it is wired.')
            ->defaultNull()
            ->cannotBeEmpty()
            ->end()
            ->floatNode('timeout')
            ->info('Seconds one push to one push service is given, connection included. A push service that hangs must not hold a worker; how many times it is tried again is the retry policy of the notifications lane, as it is for a logout token.')
            ->defaultValue(self::DEFAULT_TIMEOUT)
            ->min(0.1)
            ->end()
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $webPush = $this->own($config);
        $subject = $webPush['subject'] ?? null;
        if (! is_string($subject)) {
            $services->get(Vapid::class)->tag(DormantKeyAlgorithms::TAG);

            return;
        }
        $services->get(WebPushSender::class)->arg('$subject', $subject)->arg('$timeout', self::float($webPush, 'timeout'));
        $services->get(Vapid::class)->tag(self::ALGORITHM_TAG);
        $services->get(WebPushApprovalChannel::class)->tag(self::CHANNEL_TAG);
    }
}
