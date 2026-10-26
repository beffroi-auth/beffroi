<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\PhpStan;

use function array_map;
use function implode;
use function ltrim;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\GroupUse;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\UseItem;
use PhpParser\NodeFinder;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use function sprintf;
use function str_starts_with;
use function strtolower;

/**
 * Section 8 of the specification: the classes and the constants never used, in the brick and in its consumers, and
 * those used in the files named only (OPENSSL_ZERO_PADDING in the decryptor of Enc, enc.md E-16).
 * ekino/phpstan-banned-code bans function names and whole node types; this rule reads every name written inside
 * a class, an enum, an interface or a trait, and every name a use statement imports.
 *
 * @implements Rule<Node>
 */
final class BannedNamesRule implements Rule
{
    /**
     * @var array<string, string> the banned names, lowercased, mapped to the spelling of the configuration
     */
    private array $names = [];

    /**
     * @var array<string, array{spelling: string, allowedIn: list<string>}> the confined names, lowercased
     */
    private array $confined = [];

    /**
     * @param list<string> $names
     * @param list<array{name: string, allowedIn: list<string>}> $confined the names allowed in the files listed only
     */
    public function __construct(
        array $names,
        array $confined = [],
        private readonly string $workingDirectory = '',
    ) {
        foreach ($names as $name) {
            $this->names[strtolower(ltrim($name, '\\'))] = $name;
        }
        foreach ($confined as $name) {
            $this->confined[strtolower(ltrim($name['name'], '\\'))] = [
                'spelling' => $name['name'],
                'allowedIn' => $name['allowedIn'],
            ];
        }
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $names = match (true) {
            $node instanceof ClassLike => new NodeFinder()->findInstanceOf($node, Name::class),
            $node instanceof Use_ => array_map(static fn (UseItem $use): Name => $use->name, $node->uses),
            $node instanceof GroupUse => array_map(
                static fn (UseItem $use): Name => Name::concat($node->prefix, $use->name) ?? $use->name,
                $node->uses,
            ),
            default => [],
        };

        $errors = [];
        foreach ($names as $name) {
            $message = $this->refusal($name, $scope);
            if ($message === null) {
                continue;
            }
            $errors[] = RuleErrorBuilder::message($message)->identifier('beffroi.bannedName')->line($name->getStartLine())->nonIgnorable()->build();
        }

        return $errors;
    }

    private function refusal(Name $name, Scope $scope): ?string
    {
        $banned = $this->spelling($name, $this->names);
        if ($banned !== null) {
            return sprintf('%s is never used: section 8 of the specification bans it.', $banned);
        }
        $confined = $this->spelling($name, $this->confined);
        if ($confined === null) {
            return null;
        }
        foreach ($confined['allowedIn'] as $path) {
            if (str_starts_with($scope->getFile(), $this->workingDirectory . '/' . $path)) {
                return null;
            }
        }

        return sprintf(
            '%s is used in %s only: section 8 of the specification confines it there.',
            $confined['spelling'],
            implode(', ', $confined['allowedIn']),
        );
    }

    /**
     * The entry of $entries that $name names, as written, resolved or namespaced.
     *
     * @template T
     *
     * @param array<string, T> $entries keyed by the lowercased name
     *
     * @return ?T
     */
    private function spelling(Name $name, array $entries): mixed
    {
        $candidates = [$name->toLowerString()];
        foreach (['resolvedName', 'namespacedName'] as $attribute) {
            $resolved = $name->getAttribute($attribute);
            if ($resolved instanceof Name) {
                $candidates[] = $resolved->toLowerString();
            }
        }
        foreach ($candidates as $candidate) {
            if (isset($entries[$candidate])) {
                return $entries[$candidate];
            }
        }

        return null;
    }
}
