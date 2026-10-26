<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EmailAddressTest extends TestCase
{
    #[Test]
    #[DataProvider('provideValidAddresses')]
    public function itAcceptsAnAddress(string $value): void
    {
        // When / Then
        static::assertSame($value, (string) new EmailAddress($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidAddresses(): iterable
    {
        yield 'ascii' => ['alice@acme.example'];
        yield 'unicode local part' => ['zoé@acme.example'];
    }

    #[Test]
    #[DataProvider('provideInvalidAddresses')]
    public function itRejectsAnInvalidAddress(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new EmailAddress($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidAddresses(): iterable
    {
        yield 'empty' => [''];
        yield 'no at sign' => ['alice.acme.example'];
        yield 'no domain' => ['alice@'];
        yield 'space' => ['alice smith@acme.example'];
    }

    /**
     * RFC 4343 §3: a domain is compared without regard to ASCII case, which is how an upstream provider
     * answers for one (issue #781).
     */
    #[Test]
    #[DataProvider('provideDomains')]
    public function itNamesItsDomainInLowercase(string $value, string $domain): void
    {
        // When / Then
        static::assertSame($domain, new EmailAddress($value)->domain());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDomains(): iterable
    {
        yield 'in lowercase' => ['alice@acme.example', 'acme.example'];
        yield 'in another case' => ['Alice@Acme.EXAMPLE', 'acme.example'];
        yield 'after the last at sign of a quoted local part' => ['"alice@home"@acme.example', 'acme.example'];
    }

    /**
     * Issue #781: one mailbox whatever the case it is written in, the local part included, every server a
     * person reads their mail on ignoring it.
     */
    #[Test]
    #[DataProvider('provideMailboxes')]
    public function itTellsTheSameMailbox(string $one, string $other, bool $same): void
    {
        // When / Then
        static::assertSame($same, new EmailAddress($one)->isTheSameMailboxAs(new EmailAddress($other)));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function provideMailboxes(): iterable
    {
        yield 'as it was written' => ['alice@acme.example', 'alice@acme.example', true];
        yield 'the domain in another case' => ['alice@acme.example', 'alice@ACME.example', true];
        yield 'the local part in another case' => ['alice@acme.example', 'Alice@acme.example', true];
        yield 'a local part in Unicode in another case' => ['zoé@acme.example', 'ZOÉ@acme.example', true];
        yield 'another domain' => ['alice@acme.example', 'alice@acme.test', false];
        yield 'another local part' => ['alice@acme.example', 'bob@acme.example', false];
    }

    /**
     * Decision 0029, beffroi/saml S-60: an address however it was written holds its domain as its A-label, read by the
     * one rule of the domain, and its local part as it was written.
     */
    #[Test]
    #[DataProvider('provideSpellings')]
    public function itReadsAnAddressOfAnySpelling(string $written, string $read): void
    {
        // When / Then
        static::assertSame($read, EmailAddress::ofAnySpelling($written)->value);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSpellings(): iterable
    {
        yield 'in lowercase' => ['alice@acme.example', 'alice@acme.example'];
        yield 'the domain in capitals' => ['alice@ACME.Example', 'alice@acme.example'];
        yield 'the local part in capitals' => ['Alice@acme.example', 'Alice@acme.example'];
        yield 'the domain in a U-label' => ['alice@bücher.example', 'alice@xn--bcher-kva.example'];
        yield 'the domain in a U-label in capitals' => ['alice@BÜCHER.example', 'alice@xn--bcher-kva.example'];
        yield 'a local part in Unicode' => ['zoé@Bücher.example', 'zoé@xn--bcher-kva.example'];
        yield 'after the last at sign of a quoted local part' => ['"alice@home"@Acme.example', '"alice@home"@acme.example'];
    }

    /**
     * Decision 0029, beffroi/saml S-60: what holds no "@", a domain the rule refuses and a local part this class
     * refuses are no address of any spelling.
     */
    #[Test]
    #[DataProvider('provideUnreadSpellings')]
    public function itRefusesWhatItCannotRead(string $written): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        EmailAddress::ofAnySpelling($written);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnreadSpellings(): iterable
    {
        yield 'no at sign' => ['alice.acme.example'];
        yield 'a domain of one label' => ['alice@localhost'];
        yield 'a local part with a space' => ['alice smith@acme.example'];
        yield 'an empty local part' => ['@acme.example'];
    }
}
