<?php

declare(strict_types=1);

namespace App\Tests;

use Doctrine\ORM\EntityManagerInterface;

/**
 * Empties the tables before each test, so that every test starts from the same database.
 */
trait DatabaseReset
{
    protected static function resetDatabase(): void
    {
        $entityManager = self::entityManager();
        $entityManager->getConnection()->executeStatement('TRUNCATE lead, admin RESTART IDENTITY');
        $entityManager->clear();
    }

    protected static function entityManager(): EntityManagerInterface
    {
        return static::getContainer()->get(EntityManagerInterface::class);
    }
}
