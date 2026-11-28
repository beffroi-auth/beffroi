<?php

declare(strict_types=1);

namespace App\Administration\Controller;

use App\Administration\AdministrationAnswer;
use App\Administration\PersonDocument;
use App\Http\RequestContextFactory;
use function array_is_list;
use Beffroi\Core\Application\Identity\Member\UsernameMember;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UsernameRefusedException;
use Beffroi\Oidc\Application\Administration\AdministeredDescription;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use function explode;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use function sprintf;
use function strtolower;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;
use function trim;

/**
 * Changes what the account of a person of the tenant says, from a merge patch (RFC 7396) of the document `GET /users`
 * writes: its `username`, and its `claims`, a claim set to null taken away (decision 0038). All of it is written or
 * none: each value that changed is a row of the history of the person, and the patch one act of theirs, both naming the
 * administrator. The answer writes the account and its claims as they now are, so that nothing reads the person again.
 */
#[AsController]
final readonly class UserDescriptionController
{
    public const string MERGE_PATCH = 'application/merge-patch+json';

    private const string CLAIMS = 'claims';

    private const string ASKED = 'A person is changed by a JSON merge patch (RFC 7396, "application/merge-patch+json") of their "username" and of their "claims".';

    public function __construct(
        private AdministeredDescription $descriptions,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route(
        '/users/{id}',
        name: 'beffroi_administration_user_description',
        requirements: ['id' => '[0-9a-fA-F-]{36}'],
        methods: ['PATCH'],
    )]
    public function __invoke(ActingAdministrator $administrator, Request $request, string $id): Response
    {
        $patch = self::patch($request);
        if ($patch === null) {
            return AdministrationAnswer::refusal(Response::HTTP_BAD_REQUEST, 'invalid_request', self::ASKED);
        }
        try {
            $said = self::said($patch);
            $user = Uuid::isValid($id)
                ? $this->descriptions->describe($administrator, Uuid::fromString($id), $said, $this->contexts->fromRequest($request))
                : null;
        } catch (InvalidArgumentException|UsernameRefusedException $exception) {
            return AdministrationAnswer::refusal(Response::HTTP_BAD_REQUEST, 'invalid_request', $exception->getMessage());
        } catch (UserAlreadyExistsException) {
            return AdministrationAnswer::refusal(Response::HTTP_CONFLICT, 'conflict', 'The tenant has a person of this username already.');
        }
        if ($user === null) {
            return AdministrationAnswer::refusal(Response::HTTP_NOT_FOUND, 'not_found', 'The tenant has no person of this identifier.');
        }

        return AdministrationAnswer::of(PersonDocument::account($user));
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private static function patch(Request $request): ?array
    {
        $type = strtolower(trim(explode(';', $request->headers->get('Content-Type') ?? '', 2)[0]));
        if ($type !== self::MERGE_PATCH) {
            return null;
        }
        try {
            $patch = json_decode($request->getContent(), true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return is_array($patch) && ($patch === [] || ! array_is_list($patch)) ? $patch : null;
    }

    /**
     * The members of the account the patch says, the claims among them by their names.
     *
     * @param array<array-key, mixed> $patch
     *
     * @throws InvalidArgumentException when the patch names a member of the document no patch changes
     *
     * @return array<string, mixed>
     */
    private static function said(array $patch): array
    {
        $said = [];
        foreach ($patch as $member => $value) {
            if ($member === UsernameMember::NAME) {
                $said[UsernameMember::NAME] = $value;

                continue;
            }
            if ($member !== self::CLAIMS) {
                throw new InvalidArgumentException(sprintf('A patch changes the "username" and the "claims" of a person, not "%s".', $member));
            }
            if (! is_array($value) || $value !== [] && array_is_list($value)) {
                throw new InvalidArgumentException('"claims" is an object of the claims said, by their names in OIDC Core §5.1.');
            }
            foreach ($value as $claim => $claimed) {
                if (! is_string($claim) || $claim === UsernameMember::NAME) {
                    throw new InvalidArgumentException(sprintf('"%s" is not a claim of OIDC Core §5.1.', $claim));
                }
                $said[$claim] = $claimed;
            }
        }

        return $said;
    }
}
