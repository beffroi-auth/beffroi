<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Http\Account\RecordedInformation;
use function count;
use Beffroi\Bundle\Identity\WiredClaims;
use Beffroi\Core\Domain\Identity\User;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page where a person consults what this provider holds about them (architecture §5.2): the account
 * itself, then what they told us, each thing with its label and its value. What is on it is what the
 * record holds, read at every visit, never a copy this page keeps.
 *
 * It also offers what the tenant lets that person change of themselves (issue #452), one field per claim
 * it opens and the source that created them does not hold (decision 0002), in the order the claims are wired, each of the kind the claim says it is (issue #476), and
 * what they have changed of it so far (issue #482): the question a person asks first when they read that
 * they changed something is what it said before. What the tenant opens none of is a page that reads as it
 * always did, which is what a deployment that says nothing is served: the list above it says what is
 * held either way, so a claim that cannot be changed here is on the page and not offered.
 */
final readonly class ProfilePage
{
    /**
     * A refusal to show: the claim is not this person's to change, the tenant not opening it or the source
     * that created them holding it.
     */
    public const string NOT_OPEN = 'claim_not_open';

    /**
     * A refusal to show: the value is not one that claim holds, a birthdate that is not a date for one.
     */
    public const string REFUSED = 'claim_refused';

    public function __construct(
        private WiredClaims $claims,
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param string|null $refusal a code the template translates
     */
    public function render(User $user, ?string $refusal = null, int $status = Response::HTTP_OK): Response
    {
        $changeable = [];
        foreach ($this->claims->openedTo($user) as $claim) {
            $held = $claim->of($user);
            $changeable[$claim->name()] = [
                'held' => $held,
                // the field a page offers for what is already held, which is the claim's unless the input
                // cannot carry that value: a save on an input a browser rendered empty would erase it
                // (issue #479)
                'field' => $claim->field()->forHolding($held),
            ];
        }

        return $this->pages->render(
            'account/profile.html.twig',
            [
                'user' => $user,
                'identity' => RecordedInformation::identityOf($user),
                // every claim this provider can hold, so that the line somebody reads is the line they
                // correct; how many of them are held is what the page says of the record itself
                'claims' => RecordedInformation::everyClaimOf($user),
                'held' => count(RecordedInformation::claimsOf($user)),
                'changeable' => $changeable,
                'refusal' => $refusal,
            ],
            $status,
        );
    }
}
