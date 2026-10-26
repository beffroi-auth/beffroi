<?php

declare(strict_types=1);

/*
 * The model half of "castor saml-sp" (.castor/lab/saml.php, issue #732): the documents the SimpleSAMLphp service
 * provider sent to the provider, read back by the packages that provider is built on, not by SimpleSAMLphp and not by
 * xmlsec1. Each AuthnRequest the walk captured is received by the receiver of its binding (RedirectReceiver on the
 * query string, PostReceiver on the fields of the form), its signature verified under the key of the service provider's
 * metadata, and the request validated by the model against the metadata of both roles, as the single sign-on
 * service of the provider has to when it receives it (spec/saml.md section 6.8).
 *
 * It reads a directory the walk wrote and nothing else:
 *
 *   idp-metadata.xml                  the metadata of the provider, as it served them
 *   sp-metadata.xml                   the metadata of the service provider, as it served them
 *   authn-request-redirect.url        the URL the service provider redirected the browser to
 *   authn-request-post.fields.json    the fields of the form it had the browser post, as a browser reads them
 *
 * A binding with no file is not played and is not asked for. One line per request accepted; the exit status is not 0 when
 * one is refused, with the rule the model gives. From the root of the repository, in the phpqa image (the walk runs it):
 *
 *   docker run --rm -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/demo/saml-sp-model.php var/saml-sp/captured
 */

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * @throws RuntimeException when the file cannot be read
 */
function captured(string $directory, string $name): string
{
    $contents = file_get_contents($directory . '/' . $name);
    if ($contents === false) {
        throw new RuntimeException(sprintf('%s/%s cannot be read.', $directory, $name));
    }

    return $contents;
}

$directory = $argv[1] ?? null;
if ($directory === null || ! is_dir($directory)) {
    throw new InvalidArgumentException('usage: php tests/demo/saml-sp-model.php <directory of the captured documents>');
}

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
};
$loader = SamlLoader::create();
$reader = new MetadataReader($loader, $clock);

try {
    $provider = $reader->readTrusted($loader->load(captured(
        $directory,
        'idp-metadata.xml',
    )))->identityProvider ?? throw new RuntimeException('the metadata of the provider hold no identity provider');
    $descriptor = $reader->readTrusted($loader->load(captured($directory, 'sp-metadata.xml')));
    $serviceProvider = $descriptor->serviceProvider ?? throw new RuntimeException('the metadata of the service provider hold no service provider');
    $validator = new AuthnRequestValidator($loader, $clock);

    $received = [];
    if (is_file($directory . '/authn-request-redirect.url')) {
        $url = trim(captured($directory, 'authn-request-redirect.url'));
        $received[] = new RedirectReceiver($loader)->authnRequest((string) parse_url($url, \PHP_URL_QUERY));
    }
    if (is_file($directory . '/authn-request-post.fields.json')) {
        $fields = json_decode(captured($directory, 'authn-request-post.fields.json'), true, 4, \JSON_THROW_ON_ERROR);
        if (! is_array($fields)) {
            throw new RuntimeException('authn-request-post.fields.json does not hold the fields of a form');
        }
        $received[] = new PostReceiver($loader)->authnRequest($fields);
    }
    if ($received === []) {
        throw new RuntimeException('no AuthnRequest in ' . $directory);
    }

    foreach ($received as $request) {
        $accepted = $request->validate($validator, $serviceProvider, $provider, single_sign_on_location($provider->singleSignOnServices, $request));
        printf(
            "the model accepted the AuthnRequest %s of %s over %s (%s), issued %s, RelayState of %d bytes, asking for the assertion consumer service %s\n",
            $accepted->request->id,
            $descriptor->entityId,
            $request->binding->name,
            $accepted->authentication->name,
            $accepted->request->issueInstant->format('Y-m-d\TH:i:s\Z'),
            strlen((string) $request->relayState),
            $accepted->assertionConsumerService->location,
        );
    }
} catch (Throwable $throwable) {
    // the line is written for the task that reads it, then the exception ends the process: its status is what the
    // task asserts on, as it does of the other programs of tests/demo/
    fwrite(\STDERR, sprintf("not accepted by the model: %s: %s\n", $throwable::class, $throwable->getMessage()));

    throw $throwable;
}

/**
 * The URL of the single sign-on service of the provider for the binding the request arrived over, the one it was
 * received at.
 *
 * @param list<Endpoint> $services
 *
 * @throws RuntimeException when the provider publishes none for that binding
 */
function single_sign_on_location(array $services, ReceivedAuthnRequest $request): string
{
    foreach ($services as $service) {
        if ($service->binding === $request->binding) {
            return $service->location;
        }
    }

    throw new RuntimeException(sprintf('the provider publishes no single sign-on service for %s', $request->binding->name));
}
