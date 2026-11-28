<?php

declare(strict_types=1);

namespace App\Doctrine\PersonalData;

use Doctrine\ORM\Tools\Event\GenerateSchemaEventArgs;
use Symfony\Bridge\Doctrine\SchemaListener\AbstractSchemaListener;

/**
 * Declares the table of BlindIndexDerivations in the schema the ORM assembles, as the data key store declares its own.
 */
final class BlindIndexDerivationSchemaListener extends AbstractSchemaListener
{
    public function __construct(
        private readonly BlindIndexDerivations $derivations,
    ) {
    }

    public function postGenerateSchema(GenerateSchemaEventArgs $event): void
    {
        $connection = $event->getEntityManager()->getConnection();
        $isSameDatabase = $this->getIsSameDatabaseChecker($connection);
        $event->setSchema($this->filterSchemaChanges(
            $event->getSchema(),
            $connection,
            fn () => $this->derivations->configureSchema($event->getSchema(), $isSameDatabase),
        ));
    }
}
