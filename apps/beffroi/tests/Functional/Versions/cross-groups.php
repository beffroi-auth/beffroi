<?php

declare(strict_types=1);

/*
 * A sign-in of its own, played again and again: its own kernel, its own connection, the person of its first argument
 * entering the two groups of the next two in the order they come, then leaving them, as many times as the last one
 * says, each time in a unit as a sign-in writes its memberships. VersionsUnderConcurrentWritersTest starts two at once
 * with the groups in crossed orders.
 */

use App\Kernel;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMapping;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Dotenv\Dotenv;
use Symfony\Component\Uid\Uuid;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

new Dotenv()->bootEnv(dirname(__DIR__, 3) . '/.env');

$kernel = new Kernel('test', false);
$kernel->boot();
$container = $kernel->getContainer()->get('test.service_container');
$users = $container->get('test.beffroi.users');
$manager = $container->get('doctrine.orm.entity_manager');
$memberships = $container->get(UpstreamMemberships::class);
$writes = $container->get(AtomicWritesInterface::class);
if (
    ! $users instanceof UserRepositoryInterface
    || ! $manager instanceof EntityManagerInterface
    || ! $memberships instanceof UpstreamMemberships
    || ! $writes instanceof AtomicWritesInterface
) {
    fwrite(STDERR, 'The kernel of the suite does not name the memberships.' . PHP_EOL);

    exit(1);
}
$person = Uuid::fromString($argv[1] ?? '');
$groups = [Uuid::fromString($argv[2] ?? ''), Uuid::fromString($argv[3] ?? '')];
for ($played = 0; $played < (int) ($argv[4] ?? 0); ++$played) {
    foreach ([['first', 'second'], []] as $asserted) {
        $manager->clear();
        $user = $users->find($person) ?? throw new RuntimeException('The person is gone.');
        $mapping = new GroupMapping([
            'first' => $manager->find(Group::class, $groups[0]) ?? throw new RuntimeException('A group is gone.'),
            'second' => $manager->find(Group::class, $groups[1]) ?? throw new RuntimeException('A group is gone.'),
        ]);
        $writes->atomically(static fn () => $memberships->replace($user, $asserted, $mapping));
    }
}
$kernel->shutdown();
