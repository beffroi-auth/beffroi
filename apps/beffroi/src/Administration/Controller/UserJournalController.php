<?php

declare(strict_types=1);

namespace App\Administration\Controller;

use App\Administration\AdministrationAnswer;
use App\Administration\ProvenanceDocument;
use App\Http\RequestContextFactory;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Oidc\Application\Administration\AdministeredJournal;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use function array_map;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

/**
 * The last acts of a person of the tenant, the most recent first, with the application each one was done on behalf of
 * and where it came from: what `beffroi:user:journal` prints (decision 0038). An act names its author by their kind and
 * what names them among their kind (decision 0066). Reading them is an act of the person that names the administrator
 * (`AdministeredJournal`).
 */
#[AsController]
final readonly class UserJournalController
{
    public function __construct(
        private AdministeredJournal $journal,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route('/users/{id}/journal', name: 'beffroi_administration_user_journal', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['GET'])]
    public function __invoke(ActingAdministrator $administrator, Request $request, string $id): Response
    {
        $acts = Uuid::isValid($id)
            ? $this->journal->of($administrator, Uuid::fromString($id), $this->contexts->fromRequest($request))
            : null;
        if ($acts === null) {
            return AdministrationAnswer::refusal(Response::HTTP_NOT_FOUND, 'not_found', 'Nobody of the tenant has this identifier.');
        }

        return AdministrationAnswer::of([
            'acts' => array_map(static fn (JournalEntry $entry): array => [
                'id' => $entry->id->toRfc4122(),
                'act' => $entry->act,
                'occurred_at' => AdministrationAnswer::moment($entry->occurredAt),
                'client' => $entry->client,
                'author' => $entry->author?->toDocument(),
                'provenance' => ProvenanceDocument::of($entry->context),
            ], $acts),
        ]);
    }
}
