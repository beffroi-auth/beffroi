<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\SingleLogout;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\SingleLogout\LogoutHop;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\LogoutRequester;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-32: where a chain stands is written to its document and read back whole, and a document that is not
 * one is refused; each step of section 6.6 moves it as it says.
 */
final class LogoutProgressTest extends TestCase
{
    private const string SESSION = '0199e8a4-6f00-7000-8000-000000000001';

    private const string FIRST = 'https://first.example.org/saml';

    private const string SECOND = 'https://second.example.org/saml';

    /**
     * S-32: the column of a chain holds the progress whole, the RelayState of the requester byte for byte among it.
     */
    #[Test]
    #[DataProvider('provideProgresses')]
    public function aProgressIsReadBackFromItsDocumentWhole(LogoutProgress $progress): void
    {
        // When / Then
        static::assertEquals($progress, LogoutProgress::fromDocument($progress->toDocument()));
    }

    /**
     * @return iterable<string, array{LogoutProgress}>
     */
    public static function provideProgresses(): iterable
    {
        yield 'every member' => [new LogoutProgress(
            [Uuid::fromString(self::SESSION)],
            [new LogoutHop(Uuid::fromString(self::SESSION), self::FIRST), new LogoutHop(Uuid::fromString(self::SESSION), self::SECOND)],
            self::FIRST,
            true,
            new LogoutRequester(self::SECOND, SignOutRequests::ID, "a state with spaces, ~ and \u{e9}", SignOutRequests::POST, self::SECOND . '/slo'),
            'https://demo.example/?state=x',
        )];
        yield 'nothing optional' => [new LogoutProgress(
            [],
            [],
            null,
            false,
            new LogoutRequester(self::SECOND, SignOutRequests::ID, null, SignOutRequests::REDIRECT, self::SECOND . '/slo'),
            null,
        )];
    }

    /**
     * S-32: a document edited by hand, or written by something else, is refused rather than read as a chain.
     *
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotOne')]
    public function aDocumentThatIsNotAProgressIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        LogoutProgress::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotOne(): iterable
    {
        yield 'a session that is no UUID' => [
            [
                'sessions' => ['session-1'],
                'partial' => false,
            ],
            'A member of "sessions" of a chain is not the ID of a session.',
        ];
        yield 'a session that is no string' => [
            [
                'sessions' => [1],
                'partial' => false,
            ],
            'A member of "sessions" of a chain is not the ID of a session.',
        ];
        yield 'no partial' => [[], 'The member "partial" of a chain is missing.'];
        yield 'a hop that is no object' => [
            [
                'hops' => ['hop'],
                'partial' => false,
            ],
            'The hop of a chain must be a JSON object, got string.',
        ];
        yield 'a hop whose session is no UUID' => [
            [
                'hops' => [[
                    'session' => 'session-1',
                    'service_provider' => self::FIRST,
                ]],
                'partial' => false,
            ],
            'The member "session" of a logout hop is not the ID of a session.',
        ];
        yield 'a hop with no session' => [
            [
                'hops' => [[
                    'service_provider' => self::FIRST,
                ]],
                'partial' => false,
            ],
            'The member "session" of a logout hop is not the ID of a session.',
        ];
        yield 'a hop with no service provider' => [
            [
                'hops' => [[
                    'session' => self::SESSION,
                ]],
                'partial' => false,
            ],
            'The member "service_provider" of a logout hop is missing.',
        ];
        yield 'a requester with no request' => [
            [
                'partial' => false,
                'requester' => [
                    'service_provider' => self::SECOND,
                    'answer_binding' => SignOutRequests::REDIRECT,
                    'answer_location' => self::SECOND . '/slo',
                ],
            ],
            'The member "request_id" of a logout requester is missing.',
        ];
    }

    /**
     * Section 6.6 step 3: the next service provider is the first left, taken off as it is told.
     */
    #[Test]
    public function theNextServiceProviderIsTakenOff(): void
    {
        // Given
        $progress = new LogoutProgress(
            [],
            [new LogoutHop(Uuid::fromString(self::SESSION), self::FIRST), new LogoutHop(Uuid::fromString(self::SESSION), self::SECOND)],
            null,
            false,
            null,
            null,
        );

        // When
        $next = $progress->withoutNext();

        // Then
        static::assertSame([self::FIRST, self::SECOND, null], [
            $progress->next()?->serviceProvider,
            $next->next()?->serviceProvider,
            $next->withoutNext()->next(),
        ]);
    }

    /**
     * S-33, S-34: an answer other than Success makes the chain partial, and Success does not undo it; the service
     * provider awaited is forgotten either way.
     */
    #[Test]
    public function anAnswerOtherThanSuccessMakesTheChainPartial(): void
    {
        // Given
        $progress = new LogoutProgress([], [], self::FIRST, false, null, null);

        // When
        $answered = $progress->answered(false)->awaiting(self::SECOND)->answered(true);

        // Then
        static::assertSame([true, null, false], [$answered->partial, $answered->awaitingFrom, $progress->answered(true)->partial]);
    }

    /**
     * S-30: a service provider passed over makes the chain partial.
     */
    #[Test]
    public function aServiceProviderPassedOverMakesTheChainPartial(): void
    {
        // When / Then
        static::assertTrue(new LogoutProgress([], [], null, false, null, null)->passedOver()->partial);
    }
}
