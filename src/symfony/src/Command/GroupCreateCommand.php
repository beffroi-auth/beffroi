<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Core\Exception\GroupAlreadyExistsException;
use Beffroi\Core\Application\Group\GroupProvisioner;
use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A group of the tenant (architecture §3.4, §5.5), local, as a person of the console is: the group the
 * declaration of an upstream provider maps the values it asserts to, which no provider creates (decision 0002).
 */
#[AsCommand(
    name: 'beffroi:group:create',
    description: 'Create a group of the tenant, which the declaration of an upstream provider may map the groups it asserts to.',
)]
final readonly class GroupCreateCommand
{
    public function __construct(
        private ConfiguredTenant $tenant,
        private GroupProvisioner $provisioner,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The name of the group; unique in the tenant.')]
        string $name,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        try {
            $group = $this->provisioner->create($tenant, $name);
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        } catch (GroupAlreadyExistsException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $io->definitionList(
            [
                'Name' => $group->name,
            ],
            [
                'Source' => $group->source->value,
            ],
            [
                'Identifier' => $group->id->toRfc4122(),
            ],
            [
                'Tenant' => $tenant->slug,
            ],
        );
        $io->success(sprintf('The group "%s" is created.', $group->name));

        return Command::SUCCESS;
    }
}
