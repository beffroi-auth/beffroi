<?php

declare(strict_types=1);

namespace Beffroi\Scim\Domain\Name;

use Beffroi\Scim\Domain\Error\ScimError;
use Beffroi\Scim\Domain\Error\ScimType;
use Beffroi\Scim\Exception\ScimRefusedException;

/**
 * P-21: the names one object of a body holds, two of which may not resolve to one attribute, to an attribute and one
 * of its sub-attributes, or to a schema and an attribute of it.
 */
final class ObjectNames
{
    public const int STATUS = 400;

    public const string DETAIL = 'An object of the body names one attribute twice.';

    /**
     * @var array<string, true> what a name of the object names
     */
    private array $named = [];

    /**
     * @var array<string, true> what holds something a name of the object names
     */
    private array $holding = [];

    /**
     * @throws ScimRefusedException
     */
    public function hold(AttributeName $name): void
    {
        $holders = $name->scopes();
        $scope = array_shift($holders);
        if (isset($this->named[$scope]) || isset($this->holding[$scope])) {
            throw self::twice();
        }
        foreach ($holders as $holder) {
            if (isset($this->named[$holder])) {
                throw self::twice();
            }
        }
        $this->named[$scope] = true;
        foreach ($holders as $holder) {
            $this->holding[$holder] = true;
        }
    }

    private static function twice(): ScimRefusedException
    {
        return new ScimRefusedException(new ScimError(self::STATUS, ScimType::InvalidSyntax, self::DETAIL));
    }
}
