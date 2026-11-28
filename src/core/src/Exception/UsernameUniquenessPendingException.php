<?php

declare(strict_types=1);

namespace Beffroi\Core\Exception;

use RuntimeException;

/**
 * RFC 8265 §3.3.4: whether another person holds a username cannot be told while the usernames already written are not
 * all compared by their enforced form, so that no person is created or renamed meanwhile.
 */
final class UsernameUniquenessPendingException extends RuntimeException implements ExceptionInterface
{
}
