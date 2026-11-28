<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Fido;

use App\Fido\Conformance\AttestationResultController;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\MetadataBlobStoreInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\Rs1SoftwareKey;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use function is_array;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use function strlen;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * Architecture §7, Decision 0033
 */
final class FidoConformanceTest extends BrowserTestCase
{
    private const string ORIGIN = 'https://op.test';

    /**
     * WebAuthn Level 3 §5.4, Decision 0033
     */
    #[Test]
    public function theAttestationOptionsAreDrawnForTheUserTheToolsNameWithWhatTheyAskFor(): void
    {
        // When
        $options = $this->post('/fido/conformance/attestation/options', [
            'username' => 'johndoe@example.com',
            'displayName' => 'John Doe',
            'authenticatorSelection' => [
                'residentKey' => 'required',
                'authenticatorAttachment' => 'cross-platform',
                'userVerification' => 'required',
            ],
            'attestation' => 'direct',
            'extensions' => [
                'example.extension' => true,
            ],
        ]);

        // Then
        static::assertSame('ok', $options['status']);
        static::assertSame('', $options['errorMessage']);
        static::assertSame('op.test', self::section($options, 'rp')['id']);
        static::assertSame('johndoe@example.com', self::section($options, 'user')['name']);
        static::assertSame('John Doe', self::section($options, 'user')['displayName']);
        static::assertIsString($options['challenge']);
        static::assertSame(32, strlen(Base64UrlSafe::decodeNoPadding($options['challenge'])));
        static::assertSame([-8, -7, -257, -35, -65535, -36, -258, -259, -37, -38, -39], self::column($options, 'pubKeyCredParams', 'alg'));
        static::assertSame(
            [
                'requireResidentKey' => true,
                'authenticatorAttachment' => 'cross-platform',
                'userVerification' => 'required',
                'residentKey' => 'required',
            ],
            self::section($options, 'authenticatorSelection'),
        );
        static::assertSame('direct', $options['attestation']);
        static::assertSame([], $options['excludeCredentials']);
        static::assertSame(
            [
                'example.extension' => true,
            ],
            self::section($options, 'extensions'),
        );
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'johndoe@example.com');
        static::assertSame('John Doe', $user?->profile->name);
    }

    #[Test]
    public function aPasskeyEnrolledThroughTheToolsSignsInThroughTheTools(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN);
        $enrolled = $this->post('/fido/conformance/attestation/result', $device->create($this->creationOptions('johndoe@example.com')));
        static::assertSame('ok', $enrolled['status'], json_encode($enrolled, JSON_THROW_ON_ERROR));
        $passkey = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->findByExternalId(self::tenant(), PasskeyCredential::class, $device->credentialId);
        static::assertSame(AttestationResultController::PASSKEY_NAME, $passkey?->name);

        // When
        $options = $this->post('/fido/conformance/assertion/options', [
            'username' => 'johndoe@example.com',
            'userVerification' => 'preferred',
        ]);
        $asserted = $this->post('/fido/conformance/assertion/result', $device->get(json_encode($options, JSON_THROW_ON_ERROR)));

        // Then
        static::assertSame('ok', $options['status']);
        static::assertSame('op.test', $options['rpId']);
        static::assertSame('preferred', $options['userVerification']);
        static::assertSame([Base64UrlSafe::encodeUnpadded($device->credentialId)], self::column($options, 'allowCredentials', 'id'));
        static::assertSame(
            [
                'status' => 'ok',
                'errorMessage' => '',
            ],
            $asserted,
        );
        self::reload();
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)
            ->findByUsername(self::tenant(), 'johndoe@example.com') ?? static::fail('The user is gone.');
        static::assertCount(1, self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->findActiveByUser($user, self::now()));
    }

    /**
     * Decision 0033
     */
    #[Test]
    public function aPasskeyOfTheAlgorithmOnlyTheToolsAreOfferedEnrolsAndSignsInThroughTheTools(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN, credentialKey: new Rs1SoftwareKey());
        $enrolled = $this->post('/fido/conformance/attestation/result', $device->create($this->creationOptions('rs1@example.com')));
        static::assertSame('ok', $enrolled['status'], json_encode($enrolled, JSON_THROW_ON_ERROR));

        // When
        $options = $this->post('/fido/conformance/assertion/options', [
            'username' => 'rs1@example.com',
            'userVerification' => 'preferred',
        ]);
        $asserted = $this->post('/fido/conformance/assertion/result', $device->get(json_encode($options, JSON_THROW_ON_ERROR)));

        // Then
        static::assertSame(
            [
                'status' => 'ok',
                'errorMessage' => '',
            ],
            $asserted,
        );
    }

    /**
     * WebAuthn Level 3 §5.4
     */
    #[Test]
    public function theNextAttestationOptionsExcludeThePasskeyEnrolled(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN);
        $this->post('/fido/conformance/attestation/result', $device->create($this->creationOptions('johndoe@example.com')));

        // When
        $options = $this->post('/fido/conformance/attestation/options', [
            'username' => 'johndoe@example.com',
            'displayName' => 'John Doe',
        ]);

        // Then
        static::assertSame([Base64UrlSafe::encodeUnpadded($device->credentialId)], self::column($options, 'excludeCredentials', 'id'));
    }

    #[Test]
    public function attestationOptionsWithoutUsernameAreRefused(): void
    {
        // When
        $answer = $this->post(
            '/fido/conformance/attestation/options',
            [
                'displayName' => 'John Doe',
            ],
            Response::HTTP_BAD_REQUEST,
        );

        // Then
        static::assertSame(
            [
                'status' => 'failed',
                'errorMessage' => '"username" is required.',
            ],
            $answer,
        );
    }

    /**
     * RFC 8265 §3.3, RFC 8264 §4.2.3
     */
    #[Test]
    public function attestationOptionsForAUsernameTheProfileRefusesAreRefused(): void
    {
        // When
        $answer = $this->post(
            '/fido/conformance/attestation/options',
            [
                'username' => 'john doe',
                'displayName' => 'John Doe',
            ],
            Response::HTTP_BAD_REQUEST,
        );

        // Then
        static::assertSame(
            [
                'status' => 'failed',
                'errorMessage' => 'A username holds letters and digits of any script and printable ASCII, and U+0020 is none of them (RFC 8264 §4.2).',
            ],
            $answer,
        );
    }

    #[Test]
    public function anAttestationOverAChallengeThatWasNotDrawnIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN);
        $options = $this->creationOptions('johndoe@example.com');
        $this->post('/fido/conformance/attestation/result', $device->create($options));
        $again = new SoftwareAuthenticator(self::ORIGIN);

        // When
        $answer = $this->post('/fido/conformance/attestation/result', $again->create($options), Response::HTTP_BAD_REQUEST);

        // Then
        static::assertSame('failed', $answer['status']);
        static::assertSame('No creation options were drawn with this challenge, or they were answered already.', $answer['errorMessage']);
    }

    /**
     * WebAuthn Level 3 §7.1 step 22
     */
    #[Test]
    public function anAttestationAskedForIsCheckedAgainstTheStoredMetadata(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN, attestation: 'packed');
        self::service('test.beffroi.metadata_store', MetadataBlobStoreInterface::class)
            ->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
                Uuid::fromBinary($device->aaguid)->toRfc4122(),
                [AuthenticatorStatus::USER_VERIFICATION_BYPASS],
            )]));
        $options = $this->creationOptions('johndoe@example.com', 'direct');

        // When
        $answer = $this->post('/fido/conformance/attestation/result', $device->create($options), Response::HTTP_BAD_REQUEST);

        // Then
        static::assertSame('failed', $answer['status']);
        static::assertStringContainsString('The authenticator is compromised and cannot be used', self::string($answer['errorMessage']));
    }

    #[Test]
    public function assertionOptionsForAnUnknownUserAreRefused(): void
    {
        // When
        $answer = $this->post(
            '/fido/conformance/assertion/options',
            [
                'username' => 'nobody@example.com',
            ],
            Response::HTTP_BAD_REQUEST,
        );

        // Then
        static::assertSame(
            [
                'status' => 'failed',
                'errorMessage' => 'This user is unknown.',
            ],
            $answer,
        );
    }

    /**
     * WebAuthn Level 3 §7.2 step 13
     */
    #[Test]
    public function anAssertionFromAnotherOriginIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN);
        $this->post('/fido/conformance/attestation/result', $device->create($this->creationOptions('johndoe@example.com')));
        $options = $this->post('/fido/conformance/assertion/options', [
            'username' => 'johndoe@example.com',
        ]);

        // When
        $answer = $this->post(
            '/fido/conformance/assertion/result',
            $device->atOrigin('https://phishing.example')->get(json_encode($options, JSON_THROW_ON_ERROR)),
            Response::HTTP_BAD_REQUEST,
        );

        // Then
        static::assertSame(
            [
                'status' => 'failed',
                'errorMessage' => 'invalid_credential',
            ],
            $answer,
        );
    }

    /**
     * WebAuthn Level 3 §7.2 step 17
     */
    #[Test]
    public function anAssertionWithoutTheUserVerificationAskedForIsRefused(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN, userVerified: false);
        $this->post('/fido/conformance/attestation/result', $device->create($this->creationOptions('johndoe@example.com')));
        $options = $this->post('/fido/conformance/assertion/options', [
            'username' => 'johndoe@example.com',
            'userVerification' => 'required',
        ]);

        // When
        $answer = $this->post('/fido/conformance/assertion/result', $device->get(json_encode($options, JSON_THROW_ON_ERROR)), Response::HTTP_BAD_REQUEST);

        // Then
        static::assertSame('required', $options['userVerification']);
        static::assertSame(
            [
                'status' => 'failed',
                'errorMessage' => 'invalid_credential',
            ],
            $answer,
        );
    }

    /**
     * WebAuthn Level 3 §13.4.3
     */
    #[Test]
    public function anAssertionIsAcceptedOnce(): void
    {
        // Given
        $device = new SoftwareAuthenticator(self::ORIGIN);
        $this->post('/fido/conformance/attestation/result', $device->create($this->creationOptions('johndoe@example.com')));
        $options = $this->post('/fido/conformance/assertion/options', [
            'username' => 'johndoe@example.com',
        ]);
        $assertion = $device->get(json_encode($options, JSON_THROW_ON_ERROR));
        $this->post('/fido/conformance/assertion/result', $assertion);

        // When
        $answer = $this->post('/fido/conformance/assertion/result', $assertion, Response::HTTP_BAD_REQUEST);

        // Then
        static::assertSame('failed', $answer['status']);
        static::assertSame('No request options were drawn with this challenge, or they were answered already.', $answer['errorMessage']);
    }

    private function creationOptions(string $username, string $attestation = 'none'): string
    {
        return json_encode($this->post('/fido/conformance/attestation/options', [
            'username' => $username,
            'displayName' => 'John Doe',
            'attestation' => $attestation,
        ]), JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed>|string $body
     *
     * @return array<string, mixed>
     */
    private function post(string $path, array|string $body, int $expectedStatus = Response::HTTP_OK): array
    {
        $this->browser->request(
            'POST',
            $path,
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
            ],
            is_array($body) ? json_encode($body, JSON_THROW_ON_ERROR) : $body,
        );
        $response = $this->browser->getResponse();
        $content = $response->getContent();
        static::assertIsString($content);
        static::assertSame($expectedStatus, $response->getStatusCode(), $content);
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        $answer = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        static::assertIsArray($answer);

        return self::members($answer);
    }

    /**
     * @param array<string, mixed> $answer
     *
     * @return list<mixed>
     */
    private static function column(array $answer, string $list, string $member): array
    {
        $items = $answer[$list] ?? null;
        static::assertIsArray($items, $list);
        $column = [];
        foreach ($items as $item) {
            static::assertIsArray($item);
            $column[] = $item[$member] ?? null;
        }

        return $column;
    }

    /**
     * @param array<array-key, mixed> $values
     *
     * @return array<string, mixed>
     */
    private static function members(array $values): array
    {
        $members = [];
        foreach ($values as $name => $value) {
            $members[(string) $name] = $value;
        }

        return $members;
    }

    /**
     * @param array<string, mixed> $answer
     *
     * @return array<string, mixed>
     */
    private static function section(array $answer, string $name): array
    {
        $section = $answer[$name] ?? null;
        static::assertIsArray($section, $name);

        return self::members($section);
    }
}
