<?php

declare(strict_types=1);

namespace App\Scim;

use Beffroi\Scim\Application\Request\RequestBody;
use Beffroi\Scim\Domain\Answer\ScimAnswer;
use Beffroi\Scim\Domain\Error\NotServed;
use Beffroi\Scim\Domain\Request\BodyLength;
use Beffroi\Scim\Domain\Schema\SchemaInterface;
use Beffroi\Scim\Exception\ScimRefusedException;
use Closure;
use RuntimeException;
use stdClass;
use function stream_get_contents;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The SCIM module as the application serves it (spec/scim.md section 5.2): what a request carries handed to the module,
 * and what the module answers written back.
 */
final readonly class ScimEndpoints
{
    public const string OFF = 'This deployment serves no SCIM.';

    public function __construct(
        private RequestBody $body,
        private ScimAnswers $answers,
    ) {
    }

    /**
     * Section 6.1, steps 4 and 5, then the operation, a refusal of either answered with its error.
     *
     * @param SchemaInterface $base the base schema of the endpoint
     * @param Closure(stdClass): ScimAnswer $operation
     */
    public function write(Request $request, SchemaInterface $base, Closure $operation): Response
    {
        try {
            return $this->answers->response($operation($this->body->read($request->headers->get('Content-Type'), self::bytes($request), $base)));
        } catch (ScimRefusedException $refusal) {
            return $this->answers->response(ScimAnswer::error($refusal->error));
        }
    }

    /**
     * Section 8
     */
    public function notServed(): Response
    {
        return $this->answers->response(ScimAnswer::error(NotServed::error()));
    }

    /**
     * One byte past the bound at most, enough to refuse a longer body without reading it whole (P-5).
     */
    private static function bytes(Request $request): string
    {
        $bytes = stream_get_contents($request->getContent(true), BodyLength::BYTES + 1);
        if ($bytes === false) {
            throw new RuntimeException('The body of the request could not be read.');
        }

        return $bytes;
    }
}
