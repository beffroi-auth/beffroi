<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use function array_map;
use function base64_decode;
use Dom\Element;
use function file_get_contents;
use function parse_url;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use function preg_replace;
use function preg_replace_callback;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-19 to S-21, the acceptance of issue #733 in the bundle: the SimpleSAMLphp service
 * provider of the configuration of the test, declared with encrypt_assertions, its metadata of 30 September 2026
 * accepted and its requests signed with the key of the installation they come from, is answered with an assertion that
 * only that key decrypts, signed by the tenant and addressed to it.
 */
final class EncryptedAssertionTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = ServiceProviderDocuments::SIMPLESAMLPHP;

    private const string ASSERTION_CONSUMER = 'https://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp';

    private const string SINGLE_SIGN_ON = 'https://op.test/saml/sso';

    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const string REQUEST_ID = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    /**
     * The key of the SimpleSAMLphp installation whose metadata the fixture is, a test key and not a secret.
     */
    private const string KEY = __DIR__ . '/../../../saml2-bindings/Interop/simplesamlphp/installation/cert/sp.pem';

    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(
                Uuid::v7(),
                self::tenant(),
                self::SERVICE_PROVIDER,
                ServiceProviderDocuments::simpleSamlPhp(),
                null,
                self::currentSecond(),
            ));
        $this->alice = self::userWithPassword('alice', 'correct horse battery staple');
        $this->alice->changeEmail(new EmailAddress('alice@example.com'), true, self::currentSecond());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($this->alice);
    }

    /**
     * The acceptance of issue #733, S-19: the assertion on the wire is encrypted, a saml:EncryptedAssertion and no
     * saml:Assertion in the response the page posts.
     */
    #[Test]
    public function theAssertionOnTheWireIsEncrypted(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected();

        // Then
        static::assertSame(
            ['saml:Issuer', 'ds:Signature', 'samlp:Status', 'saml:EncryptedAssertion'],
            array_map(static fn (Element $child): string => $child->nodeName, Children::all($this->response()->root())),
        );
    }

    /**
     * S-19, S-21, SAML Core §6.2: decrypted with the key of the service provider, the assertion is signed by the tenant
     * under the certificate of its metadata, addressed to that service provider and carrying its attribute.
     */
    #[Test]
    public function theDecryptedAssertionIsSignedByTheTenantForTheServiceProvider(): void
    {
        // Given
        $this->signIn($this->alice);
        $this->redirected();

        // When
        $assertion = $this->decrypted()->assertion;

        // Then
        static::assertSame(
            ['https://op.test/saml/metadata', [[self::SERVICE_PROVIDER]], self::ASSERTION_CONSUMER, ['alice@example.com']],
            [
                $assertion->issuer->entityId,
                $assertion->conditions->audiences,
                $assertion->confirmation->recipient,
                $assertion->attributes[0]->values ?? null,
            ],
        );
    }

    private function redirected(): void
    {
        $url = new RedirectSender()->authnRequest(
            new AuthnRequest(self::REQUEST_ID, self::currentSecond(), new Issuer(self::SERVICE_PROVIDER), self::SINGLE_SIGN_ON, self::ASSERTION_CONSUMER),
            new Signing(PrivateKey::fromPem((string) file_get_contents(self::KEY))),
            'state-1',
        );
        $this->browser->request('GET', parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY));
    }

    /**
     * The response the page posts, as the service provider loads it.
     */
    private function response(): Document
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $field = $this->browser->getCrawler()->filter('input[name="SAMLResponse"]')->first();

        return SamlLoader::create()->load((string) base64_decode((string) $field->attr('value'), true));
    }

    /**
     * The response as the service provider reads it once it decrypted its assertion with its key: the plaintext in
     * place of the saml:EncryptedAssertion, the signature of the response, which covered the ciphertext, taken off,
     * validated under the certificate the metadata of the tenant publish, the assertion covering itself.
     */
    private function decrypted(): AcceptedAssertion
    {
        $response = $this->response();
        $plaintext = new Decryptor(SamlLoader::create())->decrypt(
            Children::one(
                Children::one($response->root(), new Name(self::ASSERTION, 'EncryptedAssertion')),
                new Name('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData'),
            ),
            PrivateDecryptionKey::fromPem((string) file_get_contents(self::KEY)),
        );
        $assertion = (string) preg_replace('~^<\?xml[^>]*\?>\s*~', '', new Serializer()->serialize($plaintext));
        $bytes = (string) preg_replace('~(</saml:Issuer>)<ds:Signature\b.*?</ds:Signature>~s', '$1', new Serializer()->serialize($response), 1);
        $document = (string) preg_replace_callback(
            '~<saml:EncryptedAssertion\b.*</saml:EncryptedAssertion>~s',
            static fn (): string => $assertion,
            $bytes,
        );

        return new ResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard())->validate(
            UnverifiedResponse::of(SamlLoader::create()->load($document)),
            $this->identityProvider(),
            ExpectedResponse::toRequest(self::REQUEST_ID, self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER),
        );
    }

    private function identityProvider(): IdentityProvider
    {
        $this->browser->request('GET', '/saml/metadata');

        return (
            new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
                SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
            )->identityProvider ?? static::fail('The tenant serves no identity provider.')
        );
    }
}
