<?php

declare(strict_types=1);

namespace App\Tenant;

use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Application\Passkey\PasskeyAttestations;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\PasskeyAttestation;
use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\Tenant;
use App\Identity\WiredClaims;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use function implode;
use function is_array;
use function is_string;
use function sprintf;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Its identifier derives from its slug: renaming the slug creates another tenant.
 */
final readonly class TenantFactory
{
    /**
     * RFC 9562 §6.6, fixed for the life of the project.
     */
    private const string IDENTIFIER_NAMESPACE = '55ade059-fda4-45f4-96ca-43dc8ef74d3e';

    /**
     * @param array<array-key, mixed> $authenticationClasses class name to predicate name, in order
     * @param array<array-key, mixed> $selfServedClaims
     * @param array<array-key, mixed> $look
     * @param array<array-key, mixed> $passkeyAttestation the name of a policy under "policy", the lists it reads under
     *     "roots", "own_roots" and "models_under_alert"
     */
    public function __construct(
        private string $issuer,
        private string $slug,
        private ?string $name,
        private ClockInterface $clock,
        private AuthenticationPredicatesInterface $predicates,
        private array $authenticationClasses = [],
        private array $look = [],
        private array $selfServedClaims = [],
        private ?WiredClaims $claims = null,
        private ?PasskeyAttestations $passkeyAttestations = null,
        private array $passkeyAttestation = [],
    ) {
    }

    public function create(): Tenant
    {
        $issuer = $this->issuer();

        return new Tenant(
            self::identifier($this->slug),
            $this->slug,
            $issuer,
            $this->name ?? $issuer->host,
            $this->clock->now(),
            $this->authenticationContextPolicy(),
            $this->look(),
            $this->selfServedClaims(),
            passkeyAttestation: $this->passkeyAttestation(),
        );
    }

    /**
     * Refuses a path, which the core accepts: RFC 8414 §3 places the metadata of such an issuer where no route is.
     */
    private function issuer(): Issuer
    {
        $issuer = new Issuer($this->issuer);
        if ($issuer->path !== '') {
            throw new InvalidArgumentException(sprintf(
                'The issuer "%s" carries a path: the issuer of a tenant is an origin, the routes of the provider being served at its root.',
                $issuer->value,
            ));
        }

        return $issuer;
    }

    public function selfServedClaims(): SelfServedClaims
    {
        $names = [];
        foreach ($this->selfServedClaims as $name) {
            if (! is_string($name)) {
                throw new InvalidArgumentException('A claim a person may change of themselves is named by a string.');
            }
            if ($this->claims !== null && $this->claims->named($name) === null) {
                throw new InvalidArgumentException(sprintf(
                    'This provider holds no claim "%s" a person could change of themselves; it holds %s.',
                    $name,
                    implode(', ', $this->claims->names()),
                ));
            }
            $names[] = $name;
        }

        return new SelfServedClaims($names);
    }

    /**
     * Without the wired policies, the tenant asks for no attestation, and anything else is refused rather than dropped.
     */
    public function passkeyAttestation(): PasskeyAttestation
    {
        $none = PasskeyAttestation::none();
        $policy = $this->passkeyAttestation['policy'] ?? $none->policy->name();
        if (! is_string($policy)) {
            throw new InvalidArgumentException('A passkey attestation policy is named by a string.');
        }
        $roots = self::list($this->passkeyAttestation, 'roots');
        $ownRoots = self::list($this->passkeyAttestation, 'own_roots');
        $modelsUnderAlert = self::list($this->passkeyAttestation, 'models_under_alert');
        if ($this->passkeyAttestations === null) {
            if ($policy !== $none->policy->name() || $roots !== [] || $ownRoots !== [] || $modelsUnderAlert !== []) {
                throw new InvalidArgumentException('No passkey attestation policy is wired: the tenant asks for none.');
            }

            return $none;
        }

        return $this->passkeyAttestations->named($policy, $roots, $ownRoots, $modelsUnderAlert);
    }

    /**
     * @param array<array-key, mixed> $members
     *
     * @return array<array-key, mixed>
     */
    private static function list(array $members, string $name): array
    {
        $list = $members[$name] ?? [];
        if (! is_array($list)) {
            throw new InvalidArgumentException(sprintf('The "%s" of the passkey attestation of a tenant is a list.', $name));
        }

        return $list;
    }

    public function look(): TenantLook
    {
        $logoUri = $this->look['logo_uri'] ?? null;
        $primaryColor = $this->look['primary_color'] ?? null;
        $primaryContentColor = $this->look['primary_content_color'] ?? null;

        return new TenantLook(
            is_string($logoUri) ? new LogoUri($logoUri) : null,
            is_string($primaryColor) ? $primaryColor : null,
            is_string($primaryContentColor) ? $primaryContentColor : null,
        );
    }

    public function authenticationContextPolicy(): AuthenticationContextPolicy
    {
        if ($this->authenticationClasses === []) {
            return AuthenticationContextPolicy::default();
        }
        $classes = [];
        foreach ($this->authenticationClasses as $name => $predicate) {
            if (! is_string($predicate)) {
                throw new InvalidArgumentException('An authentication context class names its predicate by a string.');
            }
            $classes[] = new AuthenticationContextClass((string) $name, $this->predicates->named($predicate));
        }

        return new AuthenticationContextPolicy($classes);
    }

    public static function identifier(string $slug): Uuid
    {
        return Uuid::v5(Uuid::fromString(self::IDENTIFIER_NAMESPACE), $slug);
    }
}
