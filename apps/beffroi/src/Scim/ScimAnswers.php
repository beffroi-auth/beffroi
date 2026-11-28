<?php

declare(strict_types=1);

namespace App\Scim;

use App\Http\ProtocolRefusalsInterface;
use App\Plane\Plane;
use Beffroi\Scim\Domain\Answer\ScimAnswer;
use Beffroi\Scim\Domain\Error\ProviderFailure;
use Beffroi\Scim\Domain\Error\ScimError;
use function implode;
use function is_array;
use function is_scalar;
use function str_starts_with;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/**
 * What the SCIM module answers, written as the response of HTTP (spec/scim.md section 5.1), for the requests under its
 * base path that this process serves.
 */
final readonly class ScimAnswers implements ProtocolRefusalsInterface
{
    /**
     * The detail of an error whose status HTTP gives no reason phrase.
     */
    public const string REFUSED = 'The provider refused this request.';

    public function __construct(
        private Plane $plane,
    ) {
    }

    public function serves(Request $request): bool
    {
        $path = $request->getPathInfo();

        return ($path === ScimRoutes::BASE_PATH || str_starts_with($path, ScimRoutes::BASE_PATH . '/')) && $this->plane->serves(ScimRoutes::USERS);
    }

    public function response(ScimAnswer $answer): Response
    {
        return new Response($answer->body(), $answer->status, $answer->headers());
    }

    public function refusal(int $status, string $detail, array $headers = []): Response
    {
        return $this->response(ScimAnswer::error(new ScimError($status, null, $detail), $headers));
    }

    /**
     * Spec/scim.md P-19, section 6.12: an error raised around the module keeps its status and its headers, and says
     * its status rather than its message, which may name the path; anything else is a failure that says nothing.
     */
    public function failure(Throwable $throwable): Response
    {
        if ($throwable instanceof HttpExceptionInterface) {
            $status = $throwable->getStatusCode();

            return $this->refusal($status, Response::$statusTexts[$status] ?? self::REFUSED, self::headers($throwable->getHeaders()));
        }

        return $this->response(ScimAnswer::error(ProviderFailure::error()));
    }

    /**
     * @param array<array-key, mixed> $headers
     *
     * @return array<string, string>
     */
    private static function headers(array $headers): array
    {
        $written = [];
        foreach ($headers as $name => $value) {
            $values = [];
            foreach (is_array($value) ? $value : [$value] as $one) {
                if (is_scalar($one)) {
                    $values[] = (string) $one;
                }
            }
            $written[(string) $name] = implode(', ', $values);
        }

        return $written;
    }
}
