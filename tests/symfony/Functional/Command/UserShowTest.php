<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.5, decision 0002: beffroi:user:show names where a person and each of their memberships
 * come from, the source being what wins over a manual edit.
 */
final class UserShowTest extends ConsoleTestCase
{
    #[Test]
    #[DataProvider('provideSources')]
    public function theSourceOfAPersonIsShown(UserSource $source, string $shown): void
    {
        // Given
        $user = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now(), source: $source);
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($shown, self::displayed($tester, 'Source'));
    }

    /**
     * @return iterable<string, array{UserSource, string}>
     */
    public static function provideSources(): iterable
    {
        yield 'local' => [UserSource::local(), 'local'];
        yield 'an upstream provider holding claims' => [
            UserSource::upstream('https://idp.acme.example/saml', ['email', 'given_name']),
            'https://idp.acme.example/saml, holding email, given_name',
        ];
        yield 'an upstream provider holding nothing' => [
            UserSource::upstream('https://idp.acme.example/saml', []),
            'https://idp.acme.example/saml',
        ];
    }

    #[Test]
    public function theGroupsOfAPersonAreShownWithTheSourceOfEachMembership(): void
    {
        // Given
        $user = self::user();
        self::membership($user, 'sales', GroupSource::UpstreamClaims);
        self::membership($user, 'admins', GroupSource::Local);

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'alice',
        ]);

        // Then
        $added = self::now()->format('Y-m-d H:i:s');
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertMatchesRegularExpression('/^\s*Group\s+Source\s+Added\s*$/m', $tester->getDisplay(true));
        static::assertMatchesRegularExpression(sprintf('/^\s*admins\s+local\s+%s\s*$/m', $added), $tester->getDisplay(true));
        static::assertMatchesRegularExpression(sprintf('/^\s*sales\s+upstream_claims\s+%s\s*$/m', $added), $tester->getDisplay(true));
    }

    #[Test]
    public function aPersonInNoGroupIsSaidToBe(): void
    {
        // Given
        self::user();

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The user is in no group.', $tester->getDisplay(true));
    }

    private static function membership(User $user, string $name, GroupSource $source): void
    {
        $group = new Group(Uuid::v7(), self::tenant(), $name, GroupSource::Local, self::now());
        self::entityManager()->persist($group);
        self::entityManager()->flush();
        self::service('test.beffroi.group_memberships', GroupMembershipRepositoryInterface::class)
            ->save(new GroupMembership(Uuid::v7(), $group, $user, $source, self::now()));
    }
}
