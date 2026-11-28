<?php

declare(strict_types=1);

namespace App\Configuration;

use App\Plane\Plane;
use App\Scim\ScimAnswers;
use App\Scim\ScimEndpoints;
use Beffroi\Scim\Application\Request\RequestBody;
use Beffroi\Scim\Domain\Name\BodyNames;
use Beffroi\Scim\Domain\Name\Schemas;
use Beffroi\Scim\Domain\Schema\EnterpriseUserSchema;
use Beffroi\Scim\Domain\Schema\GroupSchema;
use Beffroi\Scim\Domain\Schema\UserSchema;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/**
 * spec/scim.md section 5.1
 */
final readonly class ScimSection extends ConfigurationSection
{
    public const string ROLE = 'beffroi.scim.role';

    public const string ANSWERS = 'beffroi.scim.answers';

    private const string SCHEMA_TAG = 'beffroi.scim.schema';

    private const string ENDPOINTS = 'beffroi.scim.endpoints';

    public function name(): string
    {
        return 'scim';
    }

    public function describe(NodeBuilder $children): void
    {
        $children
            ->arrayNode('scim')
            ->info('SCIM 2.0 (beffroi/scim, spec/scim.md): the service provider of RFC 7643 and RFC 7644 that the directories of the tenant push its persons and groups to, under /scim/v2 on the protocol plane, switched by "enabled", which may be an environment variable, read when the container builds what the module changes. Disabled, the default, nothing of the module is built and every route of it answers 404.')
            ->canBeEnabled()
            ->children()
            ->append(self::enabled())
            ->end()
            ->end();
    }

    public function load(array $config, ServicesConfigurator $services, bool $debug): void
    {
        $services->set(self::ROLE, RoleSwitch::class)->args([self::boolean($this->own($config), 'enabled')]);
        foreach ([UserSchema::class, EnterpriseUserSchema::class, GroupSchema::class] as $schema) {
            $services->set($schema)->tag(self::SCHEMA_TAG);
        }
        $services->set(Schemas::class)->args([tagged_iterator(self::SCHEMA_TAG)]);
        $services->set(BodyNames::class)->autowire();
        $services->set(RequestBody::class)->autowire();
        $services->set(self::ANSWERS, ScimAnswers::class)->args(['%' . Plane::PARAMETER . '%']);
        self::servedBy($services, ScimAnswers::class, self::ANSWERS, self::ROLE);
        $services->set(self::ENDPOINTS, ScimEndpoints::class)->args([service(RequestBody::class), service(self::ANSWERS)]);
        self::servedBy($services, ScimEndpoints::class, self::ENDPOINTS, self::ROLE);
    }
}
