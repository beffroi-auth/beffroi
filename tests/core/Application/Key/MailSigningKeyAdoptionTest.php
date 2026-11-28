<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Domain\Author\AnAdministrator;
use Beffroi\Core\Application\Key\MailSigningKeyAdoption;
use Beffroi\Core\Bridge\InMemory\InMemoryMailSigningKeyRepository;
use Beffroi\Core\Domain\Event\MailSigningKeyRemoved;
use Beffroi\Core\Domain\Event\MailSigningKeySet;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Key\MailSigningKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0038
 */
final class MailSigningKeyAdoptionTest extends TestCase
{
    private InMemoryMailSigningKeyRepository $keys;

    private RecordingEventDispatcher $events;

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryMailSigningKeyRepository();
        $this->events = new RecordingEventDispatcher();
    }

    #[Test]
    public function theKeySetIsTheCurrentKeyOfItsFormat(): void
    {
        // Given
        $key = $this->key('A', '-1 day');

        // When
        $this->adoption()->adoptByAnAdministrator($key, self::administrator(), Fixtures::context());

        // Then
        static::assertSame($key, $this->keys->current($this->tenant, 'smime'));
    }

    #[Test]
    public function theKeyItReplacesIsServedAndNoLongerCurrent(): void
    {
        // Given
        $replaced = $this->key('A', '-2 days');
        $this->keys->save($replaced);
        $key = $this->key('B', '-1 day');

        // When
        $this->adoption()->adoptByAnAdministrator($key, self::administrator(), Fixtures::context());

        // Then
        static::assertSame([$key, $replaced], $this->keys->ofKind($this->tenant, 'smime'));
        static::assertEquals(Fixtures::now(), $replaced->replacedAt);
    }

    #[Test]
    public function aKeyOfAnotherFormatIsNotReplaced(): void
    {
        // Given
        $other = $this->key('A', '-2 days', 'pgp');
        $this->keys->save($other);

        // When
        $this->adoption()->adoptByAnAdministrator($this->key('B', '-1 day'), self::administrator(), Fixtures::context());

        // Then
        static::assertTrue($other->isCurrent());
    }

    #[Test]
    public function theKeySetAgainStaysCurrent(): void
    {
        // Given
        $key = $this->key('A', '-1 day');
        $this->keys->save($key);

        // When
        $this->adoption()->adoptByAnAdministrator($key, self::administrator(), Fixtures::context());

        // Then
        static::assertTrue($key->isCurrent());
    }

    #[Test]
    public function settingAKeyIsAnActThatNamesTheAdministrator(): void
    {
        // When
        $this->adoption()->adoptByAnAdministrator($this->key('A', '-1 day'), self::administrator(), Fixtures::context());

        // Then
        $acts = $this->events->of(MailSigningKeySet::class);
        static::assertCount(1, $acts);
        static::assertSame([str_repeat('A', 64), 'smime', 'administrator-subject'], [$acts[0]->fingerprint, $acts[0]->kind, $acts[0]->administrator->value]);
    }

    #[Test]
    public function aRemovedKeyIsServedNoMore(): void
    {
        // Given
        $key = $this->key('A', '-1 day');
        $this->keys->save($key);

        // When
        $this->adoption()->removeByAnAdministrator($key, self::administrator(), Fixtures::context());

        // Then
        static::assertSame([], $this->keys->ofKind($this->tenant, 'smime'));
    }

    #[Test]
    public function removingAKeyIsAnActThatNamesTheAdministrator(): void
    {
        // Given
        $key = $this->key('A', '-1 day');
        $this->keys->save($key);

        // When
        $this->adoption()->removeByAnAdministrator($key, self::administrator(), Fixtures::context());

        // Then
        $acts = $this->events->of(MailSigningKeyRemoved::class);
        static::assertCount(1, $acts);
        static::assertEquals(new AnAdministrator(new Subject('administrator-subject')), $acts[0]->author());
    }

    private function adoption(): MailSigningKeyAdoption
    {
        return new MailSigningKeyAdoption($this->keys, new MockClock(Fixtures::now()), $this->events);
    }

    private static function administrator(): Subject
    {
        return new Subject('administrator-subject');
    }

    private function key(string $digit, string $setAgo, string $kind = 'smime'): MailSigningKey
    {
        return new MailSigningKey(
            $this->tenant,
            $kind,
            str_repeat($digit, 64),
            'public',
            'sealed',
            [new EmailAddress('no-reply@acme.example')],
            Fixtures::now()->modify($setAgo),
        );
    }
}
