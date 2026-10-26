<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine;

use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\AtomicWritesInterface;
use Closure;
use LogicException;
use Throwable;

/**
 * Writes kept all or none in one transaction of the connection a person is written through, the manager of
 * `User` asked of the registry at every call, as the repositories ask it (`EntityManagers`). The linked
 * identity that names the person is written in the same unit, so its manager has to share that connection,
 * or the unit would be two transactions that one failure could split: that is checked at every call rather
 * than assumed from a configuration a deployment may change.
 *
 * **The transaction of the connection and not `wrapInTransaction()` of the manager**, as the middleware
 * `doctrine_transaction` of the command bus does it: the manager closes itself when its callback throws, and
 * the rest of the request would be left a closed manager. A transaction already open around this one, a
 * handler of the command bus, nests, and nothing is kept until the outer one commits.
 *
 * **A failure leaves nothing managed.** Rolling back the connection takes the rows back and leaves the
 * manager holding the objects it flushed into them, the person it inserted among them, which a later flush of
 * the same request would write again or point a new row at. So the manager forgets everything it holds, as a
 * clear does after any failure, and the ambient tenant is read again on its next use (`TenantProvider`
 * forgets it on clear).
 */
final readonly class DoctrineAtomicWrites implements AtomicWritesInterface
{
    public function __construct(
        private EntityManagers $managers,
    ) {
    }

    public function atomically(Closure $writes): mixed
    {
        $manager = $this->managers->forClass(User::class);
        $connection = $manager->getConnection();
        if ($this->managers->forClass(LinkedIdentity::class)->getConnection() !== $connection) {
            throw new LogicException('A person and the linked identity that names it are written through two connections, so no transaction can keep them together.');
        }

        try {
            return $connection->transactional($writes);
        } catch (Throwable $failure) {
            $manager->clear();

            throw $failure;
        }
    }
}
