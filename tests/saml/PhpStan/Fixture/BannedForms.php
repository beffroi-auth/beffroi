<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\PhpStan\Fixture;

/*
 * Every form section 8 of src/saml/spec/saml.md bans, one line each, and the lines that must pass. It is analysed by
 * `castor phpstan-saml-rules` under .ci-tools/phpstan-saml-rules.neon, which is the rules of .ci-tools/phpstan-saml.neon
 * pointed at this file alone, and by no other analysis, nor by the suite, nor by the formatter or Rector: it is not
 * code, it is the question put to the rules.
 *
 * A line that ends in `// error: <message>` must be refused by the rules of section 8 (identifiers beffroi.bannedCall,
 * beffroi.bannedName, ekinoBannedCode.function and ekinoBannedCode.expression) with that message, one marker for each
 * message; a line with none must not be refused by them at all. The task fails
 * on a refusal missing and on a refusal nobody expected, so that a rule that stops firing, a rule that starts firing on
 * what it let through and a line that moved are all red. What PHPStan's other rules say of this file (an unused
 * variable, a missing generic type) is not the question and is not read.
 */

final class Validator
{
    public function validateAuthenticatedByBinding(): void
    {
    }

    /**
     * @param array<mixed> $data
     */
    public function __unserialize(array $data): void
    {
    }

    public function bind(): void
    {
    }

    public function call(): void
    {
    }

    /**
     * @return \ReflectionClass<object>
     */
    public function reflector(): \ReflectionClass
    {
        throw new \LogicException('Never called.');
    }
}

/**
 * @extends \ReflectionClass<object>
 */
final class ExtendingReflection extends \ReflectionClass
{
}

/**
 * A proof of a covering signature the package would forge, to open AES-CBC under no signature at all (enc.md E-15).
 */
final class ForgedProof implements \Beffroi\Xml\Enc\CoveringSignatureInterface // error: Beffroi\Xml\Enc\CoveringSignatureInterface is never used: section 8 of the specification bans it.
{
    public function document(): \Beffroi\Xml\Core\Document
    {
        throw new \LogicException('Never called.');
    }
}

final class BannedForms
{
    /**
     * @param class-string<\ReflectionClass<object>> $reflectionClass
     */
    public function banned(
        Validator $validator,
        ?Validator $maybe,
        \Closure $closure,
        \ReflectionProperty $property,
        string $name,
        string $method,
        string $class,
        string $reflectionClass,
        callable $callable,
        array $unread,
        \ArrayObject $arrayObject,
        \ArrayIterator $iterator,
        \SplObjectStorage $storage,
        \SplDoublyLinkedList $list,
        \Beffroi\Xml\Enc\Decryptor $decryptor,
    ): void {
        // the methods banned on any receiver
        $validator->validateAuthenticatedByBinding(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $validator->VALIDATEAUTHENTICATEDBYBINDING(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $maybe?->validateAuthenticatedByBinding(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $validator->__unserialize([]); // error: __unserialize() is never called: section 8 of the specification bans it.
        Validator::validateAuthenticatedByBinding(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.

        // the functions banned
        unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        \unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        \UNSERIALIZE(''); // error: unserialize() is never called: section 8 of the specification bans it.
        session_decode(''); // error: session_decode() is never called: section 8 of the specification bans it.

        // the unserializer under the method PHP also gives it, on any receiver: the Serializable half of ArrayObject,
        // ArrayIterator, SplObjectStorage and SplDoublyLinkedList
        $arrayObject->unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        $iterator->unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        $storage->unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        $list->unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.

        // the methods of Closure, statically and on an instance
        \Closure::bind($closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        $closure->bindTo(null); // error: Closure::bindTo() is never called: section 8 of the specification bans it.
        $closure->call($validator); // error: Closure::call() is never called: section 8 of the specification bans it.

        // Reflection: instantiated, called statically, a method of an object of one, and what extends it
        $reflected = new \ReflectionClass(Validator::class); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionObject($validator); // error: ReflectionObject is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionMethod($validator, 'bind'); // error: ReflectionMethod is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionEnum(Validator::class); // error: ReflectionEnum is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionFunction($closure); // error: ReflectionFunction is never used: section 8 of the specification bans Reflection.
        $reflected = new \reflectionclass(Validator::class); // error: reflectionclass is never used: section 8 of the specification bans Reflection.
        \Reflection::getModifierNames(1); // error: Reflection is never used: section 8 of the specification bans Reflection.
        $property->setValue($validator, 1); // error: ReflectionProperty is never used: section 8 of the specification bans Reflection.
        $validator->reflector()->getName(); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new ExtendingReflection(Validator::class); // error: Beffroi\Saml\Tests\PhpStan\Fixture\ExtendingReflection is never used: section 8 of the specification bans Reflection.
        $reflected = new class(Validator::class) extends \ReflectionClass {}; // error: ReflectionClass is never used: section 8 of the specification bans Reflection.

        // a class given as a value
        $reflected = new $reflectionClass(Validator::class); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new ('ReflectionClass')(Validator::class); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new $class(); // error: An instantiation whose class PHPStan cannot read escapes the review: name the class.

        // a function, a method or a class given as a constant string or array, called
        $constant = 'unserialize';
        $constant(''); // error: unserialize() is never called: section 8 of the specification bans it.
        $constant = 'Closure::bind';
        $constant($closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        [$validator, 'validateAuthenticatedByBinding'](); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        [$closure, 'bindTo'](null); // error: Closure::bindTo() is never called: section 8 of the specification bans it.
        ['Closure', 'bind']($closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        [$storage, 'unserialize'](''); // error: unserialize() is never called: section 8 of the specification bans it.

        // the same, as an argument of any call
        array_map('unserialize', ['']); // error: unserialize() is never called: section 8 of the specification bans it.
        call_user_func('unserialize', ''); // error: unserialize() is never called: section 8 of the specification bans it.
        \Closure::fromCallable('unserialize'); // error: unserialize() is never called: section 8 of the specification bans it.
        array_map([$validator, 'validateAuthenticatedByBinding'], []); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        call_user_func('Closure::bind', $closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        array_map([\Reflection::class, 'getModifierNames'], [1]); // error: Reflection is never used: section 8 of the specification bans Reflection.

        // a first-class callable
        $first = unserialize(...); // error: unserialize() is never called: section 8 of the specification bans it.
        $first = $validator->validateAuthenticatedByBinding(...); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $first = $validator->__unserialize(...); // error: __unserialize() is never called: section 8 of the specification bans it.
        $first = \Closure::bind(...); // error: Closure::bind() is never called: section 8 of the specification bans it.
        $first = Validator::validateAuthenticatedByBinding(...); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $first = $closure->bindTo(...); // error: Closure::bindTo() is never called: section 8 of the specification bans it.
        $first = $arrayObject->unserialize(...); // error: unserialize() is never called: section 8 of the specification bans it.
        $first = session_decode(...); // error: session_decode() is never called: section 8 of the specification bans it.

        // the DOM and every parser but the one of xml-security, as model.md section 8 bans them: a class, a constant,
        // whatever its case, a loader of the DOM of PHP 8.4 on any receiver, a function
        $parsed = new \DOMDocument(); // error: DOMDocument is never used: section 8 of the specification bans it.
        $parsed = new \domdocument(); // error: DOMDocument is never used: section 8 of the specification bans it.
        $named = \DOMXPath::class; // error: DOMXPath is never used: section 8 of the specification bans it.
        $named = \DOMImplementation::class; // error: DOMImplementation is never used: section 8 of the specification bans it.
        $named = \Dom\XPath::class; // error: Dom\XPath is never used: section 8 of the specification bans it.
        $named = \SimpleXMLElement::class; // error: SimpleXMLElement is never used: section 8 of the specification bans it.
        $named = \XMLReader::class; // error: XMLReader is never used: section 8 of the specification bans it.
        $named = \XMLWriter::class; // error: XMLWriter is never used: section 8 of the specification bans it.
        $flags = LIBXML_NOENT; // error: LIBXML_NOENT is never used: section 8 of the specification bans it.
        $flags = LIBXML_DTDLOAD; // error: LIBXML_DTDLOAD is never used: section 8 of the specification bans it.
        $flags = LIBXML_DTDATTR; // error: LIBXML_DTDATTR is never used: section 8 of the specification bans it.
        $flags = LIBXML_DTDVALID; // error: LIBXML_DTDVALID is never used: section 8 of the specification bans it.
        $flags = LIBXML_XINCLUDE; // error: LIBXML_XINCLUDE is never used: section 8 of the specification bans it.
        $flags = LIBXML_PARSEHUGE; // error: LIBXML_PARSEHUGE is never used: section 8 of the specification bans it.
        $flags = LIBXML_NOBLANKS; // error: LIBXML_NOBLANKS is never used: section 8 of the specification bans it.
        $flags = LIBXML_NOCDATA; // error: LIBXML_NOCDATA is never used: section 8 of the specification bans it.
        \Dom\XMLDocument::createFromString('<a/>'); // error: createFromString() is never called: section 8 of the specification bans it.
        \Dom\XMLDocument::createFromFile($name); // error: createFromFile() is never called: section 8 of the specification bans it.
        libxml_set_external_entity_loader(null); // error: libxml_set_external_entity_loader() is never called: section 8 of the specification bans it.

        // the proof Enc asks for before it opens AES-CBC, and the result of a verification, which the package never
        // forges (enc.md E-15): named, built, implemented (ForgedProof below)
        $forged = new \Beffroi\Xml\Dsig\Verified(...$unread); // error: Beffroi\Xml\Dsig\Verified is never used: section 8 of the specification bans it.
        $named = \Beffroi\Xml\Enc\CoveringSignatureInterface::class; // error: Beffroi\Xml\Enc\CoveringSignatureInterface is never used: section 8 of the specification bans it.

        // around the names, which the rules read where they are written: the interface given another name, the model's
        // own proof built from a class-string, which passes; the one method that takes a proof, whatever its receiver
        // and as a first-class callable, is what is refused (enc.md E-15)
        class_alias('Beffroi\Xml\Enc\CoveringSignatureInterface', 'Beffroi\Saml\Tests\PhpStan\Fixture\Proof'); // error: class_alias() is never called: section 8 of the specification bans it.
        $proofClass = 'Beffroi\Saml2\Model\Internal\Response\CoveringResponseSignature';
        $forged = new $proofClass(...$unread);
        $decryptor->decryptCovered(...$unread); // error: decryptCovered() is never called: section 8 of the specification bans it.
        $first = $decryptor->decryptCovered(...); // error: decryptCovered() is never called: section 8 of the specification bans it.
        libxml_disable_entity_loader(true); // error: libxml_disable_entity_loader() is never called: section 8 of the specification bans it.
        simplexml_load_string(''); // error: simplexml_load_string() is never called: section 8 of the specification bans it.
        simplexml_load_file($name); // error: simplexml_load_file() is never called: section 8 of the specification bans it.
        simplexml_import_dom($name); // error: simplexml_import_dom() is never called: section 8 of the specification bans it.
        xml_parser_create(); // error: xml_parser_create() is never called: section 8 of the specification bans it.
        xml_parser_create_ns(); // error: xml_parser_create_ns() is never called: section 8 of the specification bans it.

        // the weak generators, as model.md section 8 bans them
        rand(); // error: rand() is never called: section 8 of the specification bans it.
        mt_rand(); // error: mt_rand() is never called: section 8 of the specification bans it.
        srand(); // error: srand() is never called: section 8 of the specification bans it.
        mt_srand(); // error: mt_srand() is never called: section 8 of the specification bans it.
        uniqid(); // error: uniqid() is never called: section 8 of the specification bans it.
        lcg_value(); // error: lcg_value() is never called: section 8 of the specification bans it.
        shuffle($unread); // error: shuffle() is never called: section 8 of the specification bans it.
        str_shuffle($name); // error: str_shuffle() is never called: section 8 of the specification bans it.
        array_rand($unread); // error: array_rand() is never called: section 8 of the specification bans it.

        // what PHPStan cannot read
        $name(); // error: A call whose function PHPStan cannot read escapes the review: name the function.
        $validator->$method(); // error: A call whose method PHPStan cannot read escapes the review: name the method.
        $unread(); // error: A call whose function PHPStan cannot read escapes the review: name the function.
        $callable(); // error: A call whose function PHPStan cannot read escapes the review: name the function.
    }

    /**
     * What ekino/phpstan-banned-code bans by default, as in the packages below this one: its functions as they are
     * written, and the statements whole. exit and dd() end what PHPStan reads of a method, so each has one of its own.
     */
    public function ekino(string $text): void
    {
        exec($text); // error: Should not use function "exec", please change the code.
        shell_exec($text); // error: Should not use function "shell_exec", please change the code.
        system($text); // error: Should not use function "system", please change the code.
        passthru($text); // error: Should not use function "passthru", please change the code.
        print_r($text); // error: Should not use function "print_r", please change the code.
        var_dump($text); // error: Should not use function "var_dump", please change the code.
        dump($text); // error: Should not use function "dump", please change the code.
        debug_backtrace(); // error: Should not use function "debug_backtrace", please change the code.
        phpinfo(); // error: Should not use function "phpinfo", please change the code.
        proc_open($text, [], $pipes); // error: Should not use function "proc_open", please change the code.
        eval($text); // error: Should not use node with type "Expr_Eval", please change the code.
        `$text`; // error: Should not use node with type "Expr_ShellExec", please change the code.
        echo $text; // error: Should not use node with type "Stmt_Echo", please change the code.
        print $text; // error: Should not use node with type "Expr_Print", please change the code.
    }

    public function dumpsAndDies(string $text): void
    {
        dd($text); // error: Should not use function "dd", please change the code.
    }

    public function exits(): void
    {
        exit(); // error: Should not use node with type "Expr_Exit", please change the code.
    }

    /**
     * What section 8 lets through: the lines below must not be refused.
     */
    public function witness(Validator $validator, \Closure $closure, string $text, \ArrayObject $arrayObject): void
    {
        $validator->bind();
        $validator->call();
        $closure();
        $closure->__invoke();
        strtoupper($text);
        array_map('strtoupper', [$text]);
        call_user_func('strtolower', $text);
        \Closure::fromCallable('strlen');
        $witnessed = strlen(...);
        $witnessed = $validator->bind(...);
        $witnessed = \Closure::fromCallable($closure);
        $witnessed = json_decode($text);
        $witnessed = serialize($text);
        $witnessed = new \ReflectionException();
        $witnessed = new \stdClass();
        $witnessed = $arrayObject->getArrayCopy();
        $witnessed = random_bytes(16);
        $witnessed = random_int(1, 6);
        $witnessed = LIBXML_NONET;
        $witnessed = \Beffroi\Xml\Enc\DecryptionKeyInterface::class;
    }
}
