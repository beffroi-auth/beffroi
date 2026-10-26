<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\PhpStan;

use function array_map;
use function count;
use function explode;
use function in_array;
use function ltrim;
use PhpParser\Node;
use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\Type\Constant\ConstantStringType;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;
use function sprintf;
use function strtolower;

/**
 * Section 8 of the specification: what beffroi/saml never calls, in src/ and in tests/, so that the binding's
 * authentication stays the word of beffroi/saml2-bindings alone and nothing builds a class of its Internal\ namespace
 * outside it (bindings.md section 6.8, B-5).
 *
 * validateAuthenticatedByBinding() of the model's validators, __unserialize() and unserialize(), whatever the receiver;
 * the functions unserialize() and session_decode(); bind(), bindTo() and call() of a Closure, statically or not; and
 * Reflection: a class of the Reflection API, or one that extends it, instantiated or called statically, and a method of
 * an object of one, however it was obtained. The ban holds in the whole package and not on the classes of Internal\
 * alone: what such a call reaches is known at runtime only (unserialize() names no class, Closure::bind() takes its
 * scope as a value), so that a ban scoped by type would have a way around it.
 *
 * A function, a method or a class given as a value rather than a name is read as PHPStan knows it: a constant string
 * or a constant callable array naming one of the above is that call, and a string PHPStan cannot read in place of a
 * name is refused; a Closure is let through. Every argument of a call is read the same way, so that a callable naming
 * one of the above handed to array_map(), call_user_func() or Closure::fromCallable() is refused where it is written;
 * a callable PHPStan cannot read handed to such a function is not seen. A first-class callable, which PHPStan visits as
 * a node of its own, is BannedCallablesRule's, which asks this rule.
 *
 * @implements Rule<CallLike>
 */
final class BannedCallsRule implements Rule
{
    /**
     * @var array<string, string> the lowercased function names, mapped to the spelling of the configuration
     */
    private array $functions = [];

    /**
     * @var array<string, string> the lowercased method names, mapped to the spelling of the configuration
     */
    private array $methods = [];

    /**
     * @var array<string, string> the lowercased methods of Closure, mapped to the spelling of the configuration
     */
    private array $closureMethods = [];

    /**
     * @var list<ObjectType>
     */
    private array $reflection = [];

    /**
     * @param list<string> $functions
     * @param list<string> $methods        banned whatever the receiver
     * @param list<string> $closureMethods banned on a Closure
     * @param list<string> $reflection     the classes of the Reflection API, each banned with what extends it
     */
    public function __construct(array $functions, array $methods, array $closureMethods, array $reflection)
    {
        foreach ($functions as $function) {
            $this->functions[strtolower($function)] = $function;
        }
        foreach ($methods as $method) {
            $this->methods[strtolower($method)] = $method;
        }
        foreach ($closureMethods as $method) {
            $this->closureMethods[strtolower($method)] = $method;
        }
        foreach ($reflection as $class) {
            $this->reflection[] = new ObjectType(ltrim($class, '\\'));
        }
    }

    public function getNodeType(): string
    {
        return CallLike::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $messages = match (true) {
            $node instanceof FuncCall => $this->functionCall($node, $scope),
            $node instanceof New_ => $this->instantiation($node, $scope),
            $node instanceof MethodCall, $node instanceof NullsafeMethodCall, $node instanceof StaticCall => $this->methodCall(
                $node,
                $scope,
            ),
            default => [],
        };
        if (! $node->isFirstClassCallable()) {
            foreach ($node->getArgs() as $argument) {
                $messages = [...$messages, ...$this->callable($scope->getType($argument->value), false)];
            }
        }

        return array_map(
            static fn (string $message): IdentifierRuleError => RuleErrorBuilder::message($message)->identifier('beffroi.bannedCall')->nonIgnorable()->build(),
            $messages,
        );
    }

    /**
     * @return list<string>
     */
    private function functionCall(FuncCall $node, Scope $scope): array
    {
        if ($node->name instanceof Name) {
            return $this->function($node->name->toString());
        }
        $callee = $scope->getType($node->name);
        if (new ObjectType('Closure')->isSuperTypeOf($callee)->yes()) {
            return [];
        }

        return $this->callable($callee, true);
    }

    /**
     * @return list<string>
     */
    private function instantiation(New_ $node, Scope $scope): array
    {
        if ($node->class instanceof Name) {
            return $this->reflection([$scope->resolveName($node->class)]);
        }
        if ($node->class instanceof Class_) {
            return $node->class->extends === null ? [] : $this->reflection([$scope->resolveName($node->class->extends)]);
        }
        $classes = $this->classes($scope->getType($node->class));
        if ($classes === []) {
            return ['An instantiation whose class PHPStan cannot read escapes the review: name the class.'];
        }

        return $this->reflection($classes);
    }

    /**
     * @return list<string>
     */
    private function methodCall(MethodCall|NullsafeMethodCall|StaticCall $node, Scope $scope): array
    {
        $receiver = match (true) {
            ! $node instanceof StaticCall => $scope->getType($node->var)->getObjectClassNames(),
            $node->class instanceof Name => [$scope->resolveName($node->class)],
            default => $this->classes($scope->getType($node->class)),
        };
        $messages = $this->reflection($receiver);
        if ($node->name instanceof Identifier) {
            return [...$messages, ...$this->method($node->name->toString(), $receiver)];
        }
        $names = $scope->getType($node->name)->getConstantStrings();
        if ($names === []) {
            return [...$messages, 'A call whose method PHPStan cannot read escapes the review: name the method.'];
        }
        foreach ($names as $name) {
            $messages = [...$messages, ...$this->method($name->getValue(), $receiver)];
        }

        return $messages;
    }

    /**
     * A callable given as a value: a constant string, "function" or "Class::method", or a constant array of an object
     * or a class and a method name. $invoked is true when the value is the callee itself, where a string or an array
     * PHPStan cannot read is refused.
     *
     * @return list<string>
     */
    private function callable(Type $type, bool $invoked): array
    {
        $messages = [];
        foreach ($type->getConstantStrings() as $string) {
            $parts = explode('::', $string->getValue(), 2);
            $messages = [
                ...$messages,
                ...(
                    count($parts) === 2
                        ? [...$this->reflection([ltrim($parts[0], '\\')]), ...$this->method($parts[1], [ltrim($parts[0], '\\')])]
                        : $this->function($parts[0])
                ),
            ];
        }
        foreach ($type->getConstantArrays() as $array) {
            $values = $array->getValueTypes();
            if (count($values) !== 2) {
                continue;
            }
            $receiver = $this->classes($values[0]);
            foreach ($values[1]->getConstantStrings() as $method) {
                $messages = [...$messages, ...$this->reflection($receiver), ...$this->method($method->getValue(), $receiver)];
            }
        }
        $unread = ! $type->isString()->no() && $type->getConstantStrings() === [] || ! $type->isArray()->no() && $type->getConstantArrays() === [];
        if ($invoked && $unread) {
            $messages[] = 'A call whose function PHPStan cannot read escapes the review: name the function.';
        }

        return $messages;
    }

    /**
     * The classes a value names: those of an object, or those a string names, constant or a class-string; none when
     * PHPStan cannot read them.
     *
     * @return list<string>
     */
    private function classes(Type $type): array
    {
        if ($type->isString()->no()) {
            return $type->getObjectClassNames();
        }
        $constants = $type->getConstantStrings();
        if ($constants !== []) {
            return array_map(static fn (ConstantStringType $class): string => ltrim($class->getValue(), '\\'), $constants);
        }

        return $type->getClassStringObjectType()->getObjectClassNames();
    }

    /**
     * @return list<string>
     */
    private function function(string $name): array
    {
        $function = $this->functions[strtolower(ltrim($name, '\\'))] ?? null;
        if ($function === null) {
            return [];
        }

        return [sprintf('%s() is never called: section 8 of the specification bans it.', $function)];
    }

    /**
     * @param list<string> $receiver the classes of the receiver, as far as PHPStan knows them
     *
     * @return list<string>
     */
    private function method(string $name, array $receiver): array
    {
        $method = $this->methods[strtolower($name)] ?? null;
        if ($method !== null) {
            return [sprintf('%s() is never called: section 8 of the specification bans it.', $method)];
        }
        $closure = $this->closureMethods[strtolower($name)] ?? null;
        if ($closure !== null && in_array('closure', array_map(strtolower(...), $receiver), true)) {
            return [sprintf('Closure::%s() is never called: section 8 of the specification bans it.', $closure)];
        }

        return [];
    }

    /**
     * @param list<string> $classes
     *
     * @return list<string>
     */
    private function reflection(array $classes): array
    {
        foreach ($classes as $class) {
            foreach ($this->reflection as $banned) {
                if ($banned->isSuperTypeOf(new ObjectType($class))->yes()) {
                    return [sprintf('%s is never used: section 8 of the specification bans Reflection.', ltrim($class, '\\'))];
                }
            }
        }

        return [];
    }
}
