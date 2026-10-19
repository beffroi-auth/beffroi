<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php55\Rector\String_\StringClassNameToClassConstantRector;
use Rector\Php71\Rector\FuncCall\RemoveExtraParametersRector;
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
    __DIR__ . '/../tests',
    __DIR__ . '/../castor.php',
    __DIR__ . '/../.castor',
    __DIR__ . '/rector.php',
    __DIR__ . '/../apps/website/src',
    __DIR__ . '/../apps/website/tests',
    __DIR__ . '/../apps/website/migrations',
]);
$builder->withSkip([
    PreferPHPUnitThisCallRector::class,
    // The fixtures of the SAML packages are data, and their interoperability projects (tests/xml-security/Dsig/
    // Fixture/real, tests/saml2-model/Interop, tests/saml2-bindings/Interop) are throwaway Composer projects run in
    // their own containers against libraries that are not dependencies here.
    __DIR__ . '/../tests/xml-security/*/Fixture/*',
    __DIR__ . '/../tests/saml2-model/Fixture/*',
    __DIR__ . '/../tests/saml2-model/Interop/*',
    __DIR__ . '/../tests/saml2-bindings/Fixture/*',
    __DIR__ . '/../tests/saml2-bindings/Interop/*',
    // The source guard tests of the SAML packages list the banned class names of their section 8 as tokens to search
    // for, never to reference: turning 'Dom\XPath' into XPath::class is the very thing the ban catches.
    StringClassNameToClassConstantRector::class => [
        __DIR__ . '/../tests/xml-security',
        __DIR__ . '/../tests/saml2-model',
    ],
    // assertNotNull() narrows a nullable node for PHPStan already; the assertInstanceOf() this rule adds after it is
    // one PHPStan then reports as always true.
    AddInstanceofAssertForNullableArgumentRector::class => [
        __DIR__ . '/../tests/xml-security',
        __DIR__ . '/../tests/saml2-model',
        __DIR__ . '/../tests/saml2-bindings',
    ],
    // openssl_sign() and openssl_verify() take a fifth parameter, the padding, on PHP 8.5 (spec/dsig.md section 13);
    // Rector reads the PHP 8.4 signatures and would strip the argument the PSS schemes pass.
    RemoveExtraParametersRector::class => [
        __DIR__ . '/../src/xml-security',
        __DIR__ . '/../tests/xml-security',
    ],
]);
$builder->withParallel();
// A hash per file, so a run re-reads only what changed. The directory is of the repository and not of
// the system temporary one, which is where the CI keeps it from one run to the next (ci.yml) and which
// a container of the QA image does not carry over. Rector drops the whole cache itself when the
// snapshot of this configuration changes, so nothing here has to be invalidated by hand.
$builder->withCache(__DIR__ . '/cache/rector');
$builder->withImportNames();

return $builder;
