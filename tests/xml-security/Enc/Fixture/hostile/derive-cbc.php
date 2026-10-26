<?php

declare(strict_types=1);

/*
 * The fixtures of AES-CBC (spec/enc.md section 9.2 rows 44 to 48, section 9.3 row 21): each one is the vector
 * ../vectors/response-encrypted-assertion-aes128-cbc.xml altered, or its plaintext encrypted again under the test keys
 * of ../keys/, with the one change its name says. Run from this directory: php derive-cbc.php. The session keys, the
 * IVs and the padding octets before the count are derived from the fixture's name, so that a run reproduces the same
 * ciphertexts; the RSA-OAEP wrapping is randomized by construction, so the wrapped keys differ from one run to the
 * next. The padding is written by hand, the count last (XML Encryption 1.1 §5.2), and the content encrypted without
 * OpenSSL's own.
 */

const BLOCK_BYTES = 16;

$vector = file_get_contents(__DIR__ . '/../vectors/response-encrypted-assertion-aes128-cbc.xml');
$private = openssl_pkey_get_private((string) file_get_contents(__DIR__ . '/../keys/test-signing-key.pem'));
$public = openssl_pkey_get_public((string) file_get_contents(__DIR__ . '/../keys/test-signing-certificate.pem'));
$stranger = openssl_pkey_get_public((string) file_get_contents(__DIR__ . '/../keys/stranger-certificate.pem'));
if ($vector === false || $private === false || $public === false || $stranger === false) {
    exit(1);
}

$keyValue = '~(?<=\n)        <xenc:CipherValue>([^<]*)</xenc:CipherValue>~';
$dataValue = '~(?<=\n)    <xenc:CipherValue>([^<]*)</xenc:CipherValue>~';
$content = '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>';

// the session key and the plaintext of the vector, to encrypt again under other keys and other paddings
preg_match($keyValue, $vector, $match);
$wrapped = base64_decode((string) preg_replace('~\s+~', '', $match[1]), true);
preg_match($dataValue, $vector, $match);
$data = base64_decode((string) preg_replace('~\s+~', '', $match[1]), true);
if ($wrapped === false || $data === false) {
    exit(1);
}
$sessionKey = null;
if (! openssl_private_decrypt($wrapped, $sessionKey, $private, OPENSSL_PKCS1_OAEP_PADDING)) {
    exit(1);
}
$padded = openssl_decrypt(
    substr($data, BLOCK_BYTES),
    'aes-128-cbc',
    (string) $sessionKey,
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
    substr($data, 0, BLOCK_BYTES),
);
if (! is_string($padded)) {
    exit(1);
}
$plaintext = substr($padded, 0, -ord($padded[strlen($padded) - 1]));

/** $bytes derived from the fixture's name and a purpose. */
$derived = static fn (string $name, string $purpose, int $bytes): string => substr(
    hash('sha512', $purpose . ':' . $name, true),
    0,
    $bytes,
);

/**
 * The IV and the ciphertext of $plaintext under $key, padded to whole blocks by octets derived from the name and a last
 * octet of $count, or of the count itself when $count is null.
 */
$encrypt = static function (
    string $name,
    string $plaintext,
    string $key,
    string $cipher,
    ?int $count = null,
) use ($derived): string {
    $length = BLOCK_BYTES - strlen($plaintext) % BLOCK_BYTES;
    $padding = $derived($name, 'padding', $length - 1) . chr($count ?? $length);
    $iv = $derived($name, 'iv', BLOCK_BYTES);
    $ciphertext = openssl_encrypt($plaintext . $padding, $cipher, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    if (! is_string($ciphertext)) {
        exit(1);
    }

    return $iv . $ciphertext;
};

/** The session key wrapped to $certificate under RSA-OAEP. */
$wrap = static function (string $key, OpenSSLAsymmetricKey $certificate): string {
    $wrapped = null;
    if (! openssl_public_encrypt($key, $wrapped, $certificate, OPENSSL_PKCS1_OAEP_PADDING)) {
        exit(1);
    }

    return (string) $wrapped;
};

/** The byte at $offset of $bytes, a negative offset counted from the end, XORed with $mask. */
$xor = static function (string $bytes, int $offset, int $mask): string {
    $at = $offset < 0 ? strlen($bytes) + $offset : $offset;

    return substr_replace($bytes, chr(ord($bytes[$at]) ^ $mask), $at, 1);
};

/** The plaintext with spaces before its closing tag, so that its length leaves $remainder over whole blocks. */
$lengthened = static function (string $plaintext, int $remainder): string {
    $spaces = ($remainder - strlen($plaintext) % BLOCK_BYTES + BLOCK_BYTES) % BLOCK_BYTES;

    return str_replace('</saml:Assertion>', str_repeat(' ', $spaces) . '</saml:Assertion>', $plaintext);
};

$base64 = static fn (string $bytes): string => rtrim(chunk_split(base64_encode($bytes), 76, "\n"), "\n");

$fresh = static fn (string $name, int $bytes): string => $derived($name, 'key', $bytes);

// [the directory, the wrapped key or null to keep the vector's, the data cipher value or null to keep the vector's]
$cases = [
    'cbc-cipher-value-iv-only-refused' => ['hostile', null, substr($data, 0, BLOCK_BYTES)],
    'cbc-cipher-value-not-whole-blocks-refused' => ['hostile', null, $data . "\x00"],
    'cbc-session-key-32-bytes-declared-aes128-cbc-refused' => [
        'hostile',
        $wrap($fresh('32', 32), $public),
        // what openssl_decrypt() makes of a 32-byte key under aes-128-cbc: its first 16 bytes (section 13)
        $encrypt('32', $plaintext, substr($fresh('32', 32), 0, 16), 'aes-128-cbc'),
    ],
    'cbc-padding-count-zero-refused' => [
        'hostile',
        $wrap($fresh('zero', 16), $public),
        $encrypt('zero', $plaintext, $fresh('zero', 16), 'aes-128-cbc', 0),
    ],
    'cbc-padding-count-seventeen-refused' => [
        'hostile',
        $wrap($fresh('seventeen', 16), $public),
        $encrypt('seventeen', $plaintext, $fresh('seventeen', 16), 'aes-128-cbc', 17),
    ],
    // the last octet of the block before the last, which the count is XORed with: 1 to 16 becomes 129 to 144
    'cbc-padding-octet-altered-refused' => ['hostile', null, $xor($data, -BLOCK_BYTES - 1, 0x80)],
    // the first octet of the ciphertext: the first block garbled, the count left in range
    'cbc-ciphertext-first-block-altered-refused' => ['hostile', null, $xor($data, BLOCK_BYTES, 0x01)],
    'cbc-key-wrapped-under-the-stranger-certificate-refused' => [
        'hostile',
        $wrap((string) $sessionKey, $stranger),
        null,
    ],
    'cbc-plaintext-with-doctype-refused' => [
        'hostile',
        $wrap($fresh('doctype', 16), $public),
        $encrypt('doctype', '<!DOCTYPE saml:Assertion>' . $plaintext, $fresh('doctype', 16), 'aes-128-cbc'),
    ],
    'cbc-plaintext-not-xml-refused' => [
        'hostile',
        $wrap($fresh('text', 16), $public),
        $encrypt('text', 'not xml at all', $fresh('text', 16), 'aes-128-cbc'),
    ],
    'cbc-padding-count-one-decrypts' => [
        'behaviour',
        $wrap($fresh('one', 16), $public),
        $encrypt('one', $lengthened($plaintext, BLOCK_BYTES - 1), $fresh('one', 16), 'aes-128-cbc'),
    ],
    'cbc-padding-of-a-whole-block-decrypts' => [
        'behaviour',
        $wrap($fresh('block', 16), $public),
        $encrypt('block', $lengthened($plaintext, 0), $fresh('block', 16), 'aes-128-cbc'),
    ],
];

foreach ($cases as $name => [$directory, $key, $value]) {
    $derivedVector = $vector;
    if ($key !== null) {
        $derivedVector = (string) preg_replace($keyValue, '        <xenc:CipherValue>' . $base64($key) . '</xenc:CipherValue>', $derivedVector);
    }
    if ($value !== null) {
        $derivedVector = (string) preg_replace($dataValue, '    <xenc:CipherValue>' . $base64($value) . '</xenc:CipherValue>', $derivedVector);
    }
    if (substr_count($derivedVector, $content) !== 1) {
        exit(1);
    }
    file_put_contents(__DIR__ . '/../' . $directory . '/' . $name . '.xml', $derivedVector);
}
printf("%d fixtures derived\n", count($cases));
