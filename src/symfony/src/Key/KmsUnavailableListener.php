<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Key;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Exception\KmsUnavailableException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Throwable;

/**
 * A KMS that does not answer or refuses is a 503 wherever it stands on the path of a request (architecture
 * §3.3, §5.4): the code page opening a secret, the token endpoint opening the key that signs on a worker
 * that has not signed yet, the enrolment of a TOTP sealing its provisioning or its secret. The exception of
 * the core crosses the firewall and the controllers as it came, and becomes here what the error page of the
 * framework renders, with a Retry-After, because the same request is served once the KMS is back; nothing
 * was refused to the user, nothing counted, nothing forgotten. The outage is announced to the audit with
 * the context of the request and the words of the KMS, and nothing of what was being opened.
 */
final readonly class KmsUnavailableListener
{
    /**
     * Above the ErrorListener of the framework (-128), which renders what it is handed.
     */
    public const int PRIORITY = 0;

    /**
     * Seconds before the client tries again (RFC 9110 §10.2.3): the time a KMS takes to come back from a
     * restart or a network blip; a KMS that lost its master key is not back on a retry, whatever the delay.
     */
    public const int RETRY_AFTER = 10;

    public function __construct(
        private TenantProvider $tenants,
        private RequestContextFactory $contexts,
        private EventDispatcherInterface $events,
    ) {
    }

    #[AsEventListener(event: KernelEvents::EXCEPTION, priority: self::PRIORITY)]
    public function __invoke(ExceptionEvent $event): void
    {
        $outage = self::outageBehind($event->getThrowable());
        if ($outage === null) {
            return;
        }
        $context = $this->contexts->fromRequest($event->getRequest());
        $this->events->dispatch(new KmsUnavailable($context->receivedAt, $this->tenants->provide(), $context, ExceptionTrail::of($outage)));
        $event->setThrowable(
            new ServiceUnavailableHttpException(
                self::RETRY_AFTER,
                'The key management service did not answer or refused; the request is served once it is back.',
                $event->getThrowable(),
            ),
        );
    }

    /**
     * The outage itself or what wrapped it on its way up; null when $throwable is no outage of the KMS.
     */
    public static function outageBehind(Throwable $throwable): ?KmsUnavailableException
    {
        for ($cause = $throwable; $cause !== null; $cause = $cause->getPrevious()) {
            if ($cause instanceof KmsUnavailableException) {
                return $cause;
            }
        }

        return null;
    }
}
