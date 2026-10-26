<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use function count;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SentSignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\SignOutNoticeRefusedException;
use Beffroi\Saml\Port\SignOutNotifierInterface;
use function in_array;
use function sprintf;
use Throwable;

/**
 * A notifier that keeps the notices it was handed, and tells every service provider but the ones a test says it cannot
 * reach, at "<entity ID>/slo", over HTTP-Redirect or, for the ones a test says, by a form over HTTP-POST, the IDs of
 * its requests numbered in their order; it refuses to write the request of the ones a test says, and fails as the KMS
 * fails while a test holds it down.
 */
final class RecordingSignOutNotifier implements SignOutNotifierInterface
{
    /**
     * @var list<SignOutNotice>
     */
    public private(set) array $notices = [];

    /**
     * What every call to notify() throws while it is set: an outage of the KMS, a failure that is no service provider's.
     */
    public ?Throwable $failure = null;

    /**
     * @param list<string> $unreachable
     * @param list<string> $posting the service providers told over HTTP-POST
     * @param list<string> $refusing the service providers whose request cannot be written
     */
    public function __construct(
        private readonly array $unreachable = [],
        private readonly array $posting = [],
        private readonly array $refusing = [],
    ) {
    }

    public function destination(Tenant $tenant, string $serviceProvider): ?string
    {
        return in_array($serviceProvider, $this->unreachable, true) ? null : $serviceProvider . '/slo';
    }

    public function notify(Tenant $tenant, SignOutNotice $notice): ?SentSignOutNotice
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
        if (in_array($notice->serviceProvider, $this->refusing, true)) {
            throw new SignOutNoticeRefusedException('The logout request of the identity provider is one its own reader refuses (spec/saml.md S-31).');
        }
        $destination = $this->destination($tenant, $notice->serviceProvider);
        if ($destination === null) {
            return null;
        }
        $this->notices[] = $notice;
        $id = self::idOf(count($this->notices));
        if (in_array($notice->serviceProvider, $this->posting, true)) {
            return new SentSignOutNotice($id, new PostedForm($destination, ['SAMLRequest' => 'told']));
        }

        return new SentSignOutNotice($id, new RedirectedMessage($destination . '?SAMLRequest=told'));
    }

    /**
     * The ID of the $nth request the notifier wrote.
     */
    public static function idOf(int $nth): string
    {
        return sprintf('_request-%d', $nth);
    }
}
