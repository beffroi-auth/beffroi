<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php55\Rector\String_\StringClassNameToClassConstantRector;
use Rector\Php71\Rector\FuncCall\RemoveExtraParametersRector;
use Rector\Php84\Rector\Foreach_\ForeachToArrayAnyRector;
use Rector\Php84\Rector\Foreach_\ForeachToArrayFindRector;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\CodeQuality\Rector\ClassMethod\AddInstanceofAssertForNullableArgumentRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\ValueObject\PhpVersion;

$builder = RectorConfig::configure();
if (file_exists('/tools/.composer/vendor-bin/phpunit/vendor/autoload.php')) {
    $builder->withAutoloadPaths(['/tools/.composer/vendor-bin/phpunit/vendor/autoload.php']);
}
$builder->withSets([
    SetList::DEAD_CODE,
    LevelSetList::UP_TO_PHP_84,
    PHPUnitSetList::PHPUNIT_CODE_QUALITY,
    PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES,
]);
$builder->withComposerBased(phpunit: true, symfony: true);
$builder->withPhpVersion(PhpVersion::PHP_84);
$builder->withPaths([
    __DIR__ . '/../src',
    __DIR__ . '/../apps/beffroi/src',
    __DIR__ . '/../apps/beffroi/config/beffroi',
    __DIR__ . '/../apps/beffroi/migrations',
    __DIR__ . '/../apps/tui/src',
    __DIR__ . '/../tests',
    __DIR__ . '/../castor.php',
    __DIR__ . '/../.castor',
    __DIR__ . '/rector.php',
]);
$builder->withSkip([
    PreferPHPUnitThisCallRector::class,
    // The demonstration and the lab of the application are no part of the product.
    __DIR__ . '/../apps/beffroi/src/Demonstration/*',
    __DIR__ . '/../apps/beffroi/src/Lab/*',
    // Fixtures are data; the interop projects run in their own containers against libraries not installed here.
    __DIR__ . '/../tests/xml-security/*/Fixture/*',
    __DIR__ . '/../tests/saml2-model/Fixture/*',
    __DIR__ . '/../tests/saml2-model/Interop/*',
    __DIR__ . '/../tests/saml2-bindings/Fixture/*',
    __DIR__ . '/../tests/saml2-bindings/Interop/*',
    __DIR__ . '/../tests/saml/Interop/*',
    // The fixture of the bans of beffroi/saml is code written to be refused, one line per banned form.
    __DIR__ . '/../tests/saml/PhpStan/Fixture/*',
    // The source guards search banned class names as strings: turning 'Dom\XPath' into XPath::class trips the ban.
    StringClassNameToClassConstantRector::class => [
        __DIR__ . '/../tests/xml-security',
        __DIR__ . '/../tests/saml2-model',
    ],
    // After assertNotNull(), the assertInstanceOf() this rule adds is one PHPStan reports as always true.
    AddInstanceofAssertForNullableArgumentRector::class => [
        __DIR__ . '/../tests/xml-security',
        __DIR__ . '/../tests/saml2-model',
        __DIR__ . '/../tests/saml2-bindings',
    ],
    // Rector reads the PHP 8.4 signatures and would strip the padding that openssl_sign() and openssl_verify()
    // take as a fifth argument on PHP 8.5.
    RemoveExtraParametersRector::class => [
        __DIR__ . '/../src/xml-security',
        __DIR__ . '/../tests/xml-security',
    ],
    // The forms of a password pass through that loop: array_any() and array_find() would put them in the arguments of
    // the frames of a stack trace, theirs and their callback's, which #[SensitiveParameter] does not reach.
    ForeachToArrayAnyRector::class => [__DIR__ . '/../src/core/src/Domain/Credential/TypedPassword.php'],
    ForeachToArrayFindRector::class => [__DIR__ . '/../src/core/src/Domain/Credential/TypedPassword.php'],
]);
$builder->withParallel();
// Not in the system temporary directory, which a QA image container does not carry over; the CI caches this one.
$builder->withCache(__DIR__ . '/cache/rector');
$builder->withImportNames();

return $builder;
