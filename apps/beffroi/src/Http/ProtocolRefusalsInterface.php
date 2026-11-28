<?php

declare(strict_types=1);

namespace App\Http;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The refusals of a protocol of the protocol plane that answers its errors with a document of its own, on the requests
 * it serves.
 */
interface ProtocolRefusalsInterface
{
    public function serves(Request $request): bool;

    /**
     * @param string $detail a sentence of the rule refused, never a value the request carried
     * @param array<string, string> $headers
     */
    public function refusal(int $status, string $detail, array $headers = []): Response;
}
