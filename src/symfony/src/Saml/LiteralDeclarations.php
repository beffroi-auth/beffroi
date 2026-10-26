<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The declarations of the configuration a compiler pass can build, those that hold no environment variable
 * (beffroi/saml, spec/saml.md section 6.2 step 1, section 6.10 step 1): what a variable says is known to the running
 * deployment only, so a declaration that holds one is left to its first use, where the container builds it with its
 * value.
 */
final readonly class LiteralDeclarations
{
    /**
     * @param array<array-key, mixed> $declarations by entity ID
     *
     * @return array<array-key, mixed> those that hold no environment variable, by entity ID
     */
    public static function of(ContainerBuilder $container, array $declarations): array
    {
        $literal = [];
        foreach ($declarations as $entityId => $declaration) {
            $environment = [];
            $container->resolveEnvPlaceholders([$entityId => $declaration], null, $environment);
            if ($environment === []) {
                $literal[$entityId] = $declaration;
            }
        }

        return $literal;
    }
}
