<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Group;

use Beffroi\Core\Domain\Author\TheHost;
use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Tests\Fixture\TextsThatAreNotPlain;
use Beffroi\Core\Exception\GroupAlreadyExistsException;
use Beffroi\Core\Application\Group\GroupProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Domain\Event\GroupCreated;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function array_map;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0002
 */
final class GroupProvisionerTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryGroupRepository $groups;

    private MockClock $clock;

    private RecordingEventDispatcher $events;

    private GroupProvisioner $provisioner;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->groups = new InMemoryGroupRepository();
        $this->clock = new MockClock('2026-10-22T12:00:00+00:00');
        $this->events = new RecordingEventDispatcher();
        $this->provisioner = new GroupProvisioner($this->groups, new SymfonyUuidGenerator(), $this->clock, $this->events);
    }

    #[Test]
    public function aGroupIsCreatedLocalInTheTenant(): void
    {
        // When
        $group = $this->provisioner->create($this->tenant, 'admins', Fixtures::context());

        // Then
        static::assertSame($group, $this->groups->findByName($this->tenant, 'admins'));
        static::assertSame($this->tenant, $group->tenant);
        static::assertSame('admins', $group->name);
        static::assertSame(GroupSource::Local, $group->source);
        static::assertEquals($this->clock->now(), $group->createdAt);
    }

    #[Test]
    public function aNameAlreadyTakenInTheTenantIsRefused(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'admins', Fixtures::context());

        // Then
        $this->expectException(GroupAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A group named "admins" already exists in this tenant.');

        // When
        $this->provisioner->create($this->tenant, 'admins', Fixtures::context());
    }

    #[Test]
    public function aNameTakenBetweenTheLookupAndTheWriteIsRefused(): void
    {
        // Given
        $provisioner = new GroupProvisioner(
            new readonly class($this->groups) implements GroupRepositoryInterface {
                public function __construct(
                    private GroupRepositoryInterface $store,
                ) {
                }

                public function findByName(Tenant $tenant, string $name): ?Group
                {
                    return null;
                }

                public function save(Group $group): void
                {
                    $this->store->save($group);
                }
            },
            new SymfonyUuidGenerator(),
            $this->clock,
            new RecordingEventDispatcher(),
        );
        $provisioner->create($this->tenant, 'admins', Fixtures::context());

        // Then
        $this->expectException(GroupAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A group named "admins" already exists in this tenant.');

        // When
        $provisioner->create($this->tenant, 'admins', Fixtures::context());
    }

    #[Test]
    public function theCreationByTheHostIsAnActOfTheTenantThatNamesIt(): void
    {
        // When
        $this->provisioner->create($this->tenant, 'auditors', Fixtures::context());

        // Then
        static::assertEquals(
            [['auditors', new TheHost()]],
            array_map(static fn (GroupCreated $act): array => [$act->group, $act->author()], $this->events->of(GroupCreated::class)),
        );
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function theCreationByAnAdministratorIsAnActThatNamesThem(): void
    {
        // When
        $this->provisioner->createByAnAdministrator($this->tenant, 'auditors', new Subject('administrator-subject'), Fixtures::context());

        // Then
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $this->events->of(GroupCreated::class)[0]->author());
    }

    #[Test]
    public function aNameIsTakenInItsTenantOnly(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->provisioner->create($other, 'admins', Fixtures::context());

        // When
        $group = $this->provisioner->create($this->tenant, 'admins', Fixtures::context());

        // Then
        static::assertSame($group, $this->groups->findByName($this->tenant, 'admins'));
    }

    #[Test]
    public function aNameDifferingByItsCaseIsAnotherGroup(): void
    {
        // Given
        $admins = $this->provisioner->create($this->tenant, 'admins', Fixtures::context());

        // When
        $capitalised = $this->provisioner->create($this->tenant, 'Admins', Fixtures::context());

        // Then
        static::assertFalse($capitalised->id->equals($admins->id));
    }

    #[Test]
    public function anEmptyNameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A group name must not be empty.');

        // When
        $this->provisioner->create($this->tenant, '', Fixtures::context());
    }

    #[Test]
    #[DataProvider('provideNamesWithWhitespaceAtAnEnd')]
    public function aNameThatBeginsOrEndsWithWhitespaceIsRefused(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A group name must not begin or end with whitespace.');

        // When
        $this->provisioner->create($this->tenant, $name, Fixtures::context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesWithWhitespaceAtAnEnd(): iterable
    {
        yield 'a space before' => [' admins'];
        yield 'a no-break space after' => ["admins\u{00A0}"];
        yield 'an ideographic space after' => ["admins\u{3000}"];
        yield 'a tab before' => ["\tadmins"];
        yield 'a line feed after' => ["admins\n"];
        yield 'a next line after' => ["admins\u{0085}"];
        yield 'nothing but spaces' => ['   '];
    }

    #[Test]
    #[DataProvider('provideNamesNotInNfc')]
    public function aNameNotInNormalizationFormCIsRefused(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A group name must be UTF-8 in Unicode Normalization Form C.');

        // When
        $this->provisioner->create($this->tenant, $name, Fixtures::context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesNotInNfc(): iterable
    {
        yield 'a decomposed accent' => ["e\u{0301}quipe"];
        yield 'bytes that are not UTF-8' => ["\xFFadmins"];
    }

    #[Test]
    public function aNameLongerThanItsColumnIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A group name must not be longer than 255 characters.');

        // When
        $this->provisioner->create($this->tenant, str_repeat('é', 256), Fixtures::context());
    }

    #[Test]
    public function aNameAsLongAsItsColumnIsTaken(): void
    {
        // When
        $group = $this->provisioner->create($this->tenant, str_repeat('é', 255), Fixtures::context());

        // Then
        static::assertSame(str_repeat('é', 255), $group->name);
    }

    #[Test]
    #[DataProvider('provideNamesThatAreNotPlainText')]
    public function aNameThatIsNotPlainTextIsRefused(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A group name must be plain text, with no control, format or line separator character.');

        // When
        $this->provisioner->create($this->tenant, $name, Fixtures::context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatAreNotPlainText(): iterable
    {
        yield from TextsThatAreNotPlain::around('admins');
    }
}
