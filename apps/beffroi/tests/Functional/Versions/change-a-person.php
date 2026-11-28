<?php

declare(strict_types=1);

/*
 * A writer of one person of its own, as a server or the worker of a deployment is: its own kernel, its own connection,
 * and as many changes as its second argument says, each on the person read again. VersionsUnderConcurrentWritersTest
 * starts two at once.
 */

use App\Kernel;
use Beffroi\Core\Domain\Identity\Profile;
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
if (! $users instanceof UserRepositoryInterface || ! $manager instanceof EntityManagerInterface) {
    fwrite(STDERR, 'The kernel of the suite does not name the persons.' . PHP_EOL);

    exit(1);
}
$id = Uuid::fromString($argv[1] ?? '');
for ($changed = 0; $changed < (int) ($argv[2] ?? 0); ++$changed) {
    $manager->clear();
    $user = $users->find($id) ?? throw new RuntimeException('The person is gone.');
    $user->updateProfile(new Profile(name: bin2hex(random_bytes(8))), new DateTimeImmutable());
    $users->save($user);
}
$kernel->shutdown();
