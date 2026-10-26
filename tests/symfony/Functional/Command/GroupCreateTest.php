<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Port\GroupRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;

/**
 * Architecture §5.5, decision 0002, issue #782: a group of the tenant is created from the console, as a person
 * is, and the declaration of an upstream provider maps the values it asserts to it.
 */
final class GroupCreateTest extends ConsoleTestCase
{
    #[Test]
    public function aGroupIsCreatedFromTheConsole(): void
    {
        // When
        $tester = self::console('beffroi:group:create', [
            'name' => 'admins',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $group = self::groupsOfTheTenant()->findByName(self::tenant(), 'admins') ?? static::fail('The group is not stored.');
        static::assertSame(GroupSource::Local, $group->source);
        static::assertSame('admins', self::displayed($tester, 'Name'));
        static::assertSame($group->id->toRfc4122(), self::displayed($tester, 'Identifier'));
    }

    #[Test]
    public function aNameAlreadyTakenIsRefused(): void
    {
        // Given
        self::console('beffroi:group:create', [
            'name' => 'admins',
        ]);

        // When
        $tester = self::console('beffroi:group:create', [
            'name' => 'admins',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('A group named "admins" already exists in this tenant.', self::flattened($tester));
    }

    #[Test]
    public function anEmptyNameIsRefusedWithoutWriting(): void
    {
        // When
        $tester = self::console('beffroi:group:create', [
            'name' => '',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('A group name must not be empty.', self::flattened($tester));
        static::assertSame(0, self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM beffroi_group'));
    }

    #[Test]
    public function nothingIsCreatedBeforeTheTenantIs(): void
    {
        // Given
        self::entityManager()->getConnection()->executeStatement('DELETE FROM beffroi_tenant');
        self::reload();

        // When
        $tester = self::console('beffroi:group:create', [
            'name' => 'admins',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('beffroi:tenant:synchronize', $tester->getDisplay());
        static::assertSame(0, self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM beffroi_group'));
    }

    private static function groupsOfTheTenant(): GroupRepositoryInterface
    {
        return self::service('test.beffroi.groups', GroupRepositoryInterface::class);
    }
}
