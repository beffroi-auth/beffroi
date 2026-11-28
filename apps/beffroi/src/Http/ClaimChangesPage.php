<?php

declare(strict_types=1);

namespace App\Http;

use Beffroi\Core\Domain\Identity\ClaimChangeQuestion;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CanPageChangesOfAPersonInterface;
use Beffroi\Core\Port\KindsOfAuthorInterface;
use Symfony\Component\HttpFoundation\Response;

final readonly class ClaimChangesPage
{
    public const string CLAIM = 'claim';

    public const string AUTHOR = 'by';

    public function __construct(
        private CanPageChangesOfAPersonInterface $changes,
        private KindsOfAuthorInterface $kinds,
        private AskedPage $page,
        private AskedPeriod $period,
        private AskedWord $word,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        $claims = $this->changes->claimsChangedOf($user);
        $question = new ClaimChangeQuestion(
            period: $this->period->asked($user),
            claim: $this->word->among(self::CLAIM, $claims),
            by: $this->word->among(self::AUTHOR, $this->kinds->kinds()),
        );

        return $this->pages->render('account/changes.html.twig', [
            'user' => $user,
            'changes' => $this->changes->pageOfChanges($user, $question, $this->page->asked()),
            'question' => $question,
            'narrowed' => $question->period !== null || $question->claim !== null || $question->by !== null,
            'claims' => $claims,
            'kinds' => $this->kinds->kinds(),
        ]);
    }
}
