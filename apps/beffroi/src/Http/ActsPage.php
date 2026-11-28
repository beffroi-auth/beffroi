<?php

declare(strict_types=1);

namespace App\Http;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\ActsOfAnAccount;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Beffroi\Core\Port\KindsOfAuthorInterface;
use Beffroi\Oidc\Domain\Administration\ReadsByAnAdministrator;
use Beffroi\Oidc\Domain\Client\ActsAboutTheirClient;
use Beffroi\Oidc\Domain\Consent\ConsentActs;
use Beffroi\Oidc\Domain\EndSession\SessionEndActs;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use function in_array;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of the acts of the signed-in person: what they did and what was done to them, the consents they gave or that
 * were taken back and the tokens an application lost when a session ended included, and the reads an administrator of
 * their tenant made of them, those they made of themselves left out.
 */
final readonly class ActsPage
{
    /**
     * @var list<string>
     */
    public const array ACTS = [
        ...ActsOfAnAccount::NAMES,
        ...SessionEndActs::NAMES,
        ...ConsentActs::NAMES,
        ...ReadsByAnAdministrator::NAMES,
    ];

    public const string ACT = 'act';

    public const string AUTHOR = 'by';

    public function __construct(
        private CanPageActsOfAPersonInterface $acts,
        private KindsOfAuthorInterface $kinds,
        private AskedPage $asked,
        private AskedPeriod $period,
        private AskedWord $word,
        private InteractionPages $pages,
        private ClientRepositoryInterface $clients,
    ) {
    }

    public function render(User $user): Response
    {
        $act = $this->word->among(self::ACT, self::ACTS);
        $question = new JournalQuestion(
            $act === null ? self::ACTS : [$act],
            period: $this->period->asked($user),
            unlessTheirOwn: ReadsByAnAdministrator::NAMES,
            by: $this->word->among(self::AUTHOR, $this->kinds->kinds()),
        );

        $acts = $this->acts->pageOfActs($user, $question, $this->asked->asked());

        return $this->pages->render('account/acts.html.twig', [
            'user' => $user,
            'acts' => $acts,
            'applications' => $this->applicationsOf($user, $acts),
            'question' => $question,
            'act' => $act,
            'narrowed' => $act !== null || $question->period !== null || $question->by !== null,
            'offered' => self::ACTS,
            'kinds' => $this->kinds->kinds(),
        ]);
    }

    /**
     * The client an act of the page is about, by the name it presents, or by its identifier once the tenant no longer
     * holds it.
     *
     * @param Listing<JournalEntry> $acts
     *
     * @return array<string, string> by the identifier of the client
     */
    private function applicationsOf(User $user, Listing $acts): array
    {
        $applications = [];
        foreach ($acts as $act) {
            $clientId = $act->client;
            if ($clientId === null || isset($applications[$clientId]) || ! in_array($act->act, ActsAboutTheirClient::NAMES, true)) {
                continue;
            }
            $applications[$clientId] = $this->clients->findByClientId($user->tenant, $clientId)?->registration->presentation->name ?? $clientId;
        }

        return $applications;
    }
}
