<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleLogout;

use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\SingleLogout\SessionParticipants;
use Beffroi\Saml\Domain\Event\ServiceProviderSignedIn;
use Beffroi\Saml\Tests\Fixture\InMemorySessionParticipations;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-26: each service provider's part in a session recorded from the event single sign-on announces, for a
 * session that still exists.
 */
final class SessionParticipantsTest extends TestCase
{
    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemorySessionParticipations $participations;

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->participations = new InMemorySessionParticipations();
        $this->session = Fixtures::session();
        $this->sessions->save($this->session);
    }

    /**
     * S-26: the row names the tenant, the session, the service provider and the instant of the sign-on.
     */
    #[Test]
    public function aSignOnIsRecordedForItsSession(): void
    {
        // When
        $this->participants()->signedIn($this->signedIn($this->session->id));

        // Then
        $recorded = $this->participations->ofSession($this->session->id)[0] ?? static::fail('Nothing was recorded.');
        static::assertSame(
            [$this->session->tenant, $this->session, ServiceProviderDocuments::SIGNED, Fixtures::now()->getTimestamp()],
            [$recorded->tenant, $recorded->session, $recorded->serviceProvider, $recorded->signedInAt->getTimestamp()],
        );
    }

    /**
     * S-26: a session that no longer exists, purged since the sign-on, is not recorded.
     */
    #[Test]
    public function aSessionThatIsGoneIsNotRecorded(): void
    {
        // Given
        $gone = Uuid::v7();

        // When
        $this->participants()->signedIn($this->signedIn($gone));

        // Then
        static::assertSame([], $this->participations->ofSession($gone));
    }

    /**
     * S-26: a session of another tenant than the event's is not recorded under it.
     */
    #[Test]
    public function aSessionOfAnotherTenantIsNotRecorded(): void
    {
        // Given
        $event = new ServiceProviderSignedIn(
            Fixtures::now(),
            Fixtures::tenant('globex', 'https://id.globex.example'),
            $this->session->id,
            ServiceProviderDocuments::SIGNED,
            $this->session->user->subject,
            Fixtures::context(),
        );

        // When
        $this->participants()->signedIn($event);

        // Then
        static::assertSame([], $this->participations->ofSession($this->session->id));
    }

    private function signedIn(Uuid $sessionId): ServiceProviderSignedIn
    {
        return new ServiceProviderSignedIn(
            Fixtures::now(),
            $this->session->tenant,
            $sessionId,
            ServiceProviderDocuments::SIGNED,
            $this->session->user->subject,
            Fixtures::context(),
        );
    }

    private function participants(): SessionParticipants
    {
        return new SessionParticipants($this->sessions, $this->participations);
    }
}
