<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Bundle\Http\Account\BreachedPasswordDemand;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Identity\User;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The page where a person replaces their own password (architecture §5.2): when it was last written,
 * whether a list of compromised passwords has since found it, the form that replaces it, and what the form
 * was refused.
 *
 * **It says when the password was last written**, which is what a page like this has to show: nothing
 * visible changes when a password does, so the date is the answer a person reads after they changed it,
 * and the one thing they can check against what they remember.
 *
 * **It says when their password has been found in a breach**, which is the one thing a person has to be
 * told rather than asked. The lane that found it wrote the date on the credential (issue #552) and this is
 * where it is read: a login inside an authorization request is not interrupted for it, and nothing of a
 * conformance run sees anything new.
 *
 * **It says so differently to a browser a login sent here**, which is the one login that is interrupted
 * for it (Account\BreachedPasswordDemand, issue #579): the sentence then says what is asked and that
 * replacing the password carries the browser on to the page it was going to. A person who leaves without
 * replacing it is asked again by the next login that serves no authorization request.
 *
 * **The length it asks for is the one the floor of its tenant asks** (PasswordLength, NIST SP 800-63B
 * §3.1.1.2): fifteen characters where the password signs its person in alone, eight where a second factor
 * is read beside it. The form declares that number and the core refuses below it, and they are one number
 * rather than two that must agree.
 *
 * **A person of a federated domain is offered no form** (decision 0029): they sign in through their
 * organisation, and a password they held before is replaced by nobody (PasswordChange).
 *
 * **A person who holds no password reads that they hold none.** Somebody who signs in by passkey alone
 * has nothing to replace here, and this page does not offer to set a first one: posing a password is an
 * enrolment, and an enrolment proves something first.
 */
final readonly class PasswordPage
{
    /**
     * What the meter in the browser writes for each of the five rungs, lowest first, each a key of the
     * translations: the words are the page's and the estimate is the script's, so a language added is a
     * language the meter speaks.
     *
     * @var list<string>
     */
    public const array RUNG_KEYS = [
        'password.strength.nothing',
        'password.strength.weak',
        'password.strength.medium',
        'password.strength.strong',
        'password.strength.very_strong',
    ];

    public function __construct(
        private ActivePassword $activePassword,
        private BreachedPasswordDemand $demands,
        private InteractionPages $pages,
        private FederatedDomains $federated,
    ) {
    }

    /**
     * @param string|null $refusal a code the template translates, read once out of the session the
     *                             redirection crossed (issue #481)
     */
    public function render(SessionInterface $httpSession, User $user, ?string $refusal = null): Response
    {
        $password = $this->activePassword->of($user);

        return $this->pages->render('account/password.html.twig', [
            'user' => $user,
            'password' => $password,
            'demanded' => $this->demands->isMade($httpSession, $password),
            'refusal' => $refusal,
            // decision 0029, beffroi/saml S-63: the password of a person of a federated domain is replaced by nobody
            'federated' => ! $this->federated->admitsLocalCredentials($user),
            'minimum' => PasswordLength::under($user->tenant->loginFloor)->minimum,
            'floor' => PlainPassword::MINIMUM_STRENGTH,
            'rungs' => self::RUNG_KEYS,
        ]);
    }
}
