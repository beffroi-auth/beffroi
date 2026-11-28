<?php

declare(strict_types=1);

namespace App\Scim;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Spec/scim.md P-19, section 6.12: what fails on a request under the base path of SCIM, its routing included, answered
 * with the error document of RFC 7644 §3.12. While SCIM is off, nothing is answered here.
 */
#[AsEventListener(event: KernelEvents::EXCEPTION, priority: self::PRIORITY)]
final readonly class ScimErrorListener
{
    /**
     * Below the listeners that log what failed and make an outage of the KMS a 503 (0), above the ErrorListener of the
     * framework (-128), which renders what nothing else answered.
     */
    public const int PRIORITY = -1;

    public function __construct(
        private ?ScimAnswers $answers = null,
    ) {
    }

    public function __invoke(ExceptionEvent $event): void
    {
        if (! $this->answers instanceof ScimAnswers || ! $this->answers->serves($event->getRequest())) {
            return;
        }
        $event->setResponse($this->answers->failure($event->getThrowable()));
    }
}
