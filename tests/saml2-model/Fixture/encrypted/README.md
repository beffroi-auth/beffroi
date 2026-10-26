# Encrypted responses

The responses whose assertion is encrypted, which `ResponseValidator` reads under the contract of section 6.7 of
`spec/model.md` (rows 38 to 51 of section 9.2, rows 23 to 25 of section 9.3). The encryptions and the signature of a
response over its ciphertext are made by xmlsec1, an implementation that is not this one: xmlsec1 1.3.7 on OpenSSL, in
Alpine 3.22 (`apk add xmlsec`), on 22 October 2026, for the test certificate of the service provider and with the test
key of the identity provider, both under `../keys/`. Each vector is the output of xmlsec1 byte for byte; the hostile
fixtures are each a vector with the one change their name says, written by `derive.php`.

## The data files

`derive.php`, run from this directory, writes the data files from `../behaviour/response-signed-assertion-accepted.xml`:

```
php derive.php data
```

| Data file | What it holds |
|---|---|
| `response-signed-assertion.data.xml` | the response in clear, unsigned, its signed assertion inside a `saml:EncryptedAssertion` and declaring `xmlns:saml` itself: xmlsec1 encrypts an element with the declarations it carries and none it inherits (enc.md section 13), and the exclusive canonical form of the assertion renders that declaration on it wherever it stands, so that its signature is unchanged |
| `response-unsigned-assertion.data.xml` | the same, the signature of the assertion taken off |
| `response-signed-response.data.xml` | the same unsigned assertion, the response carrying the template of an enveloped signature after its `Issuer`, RSA-SHA256 over SHA-256 with the exclusive transform |
| `response-signed-assertion-changed.data.xml` | the first data file, the `NameID` of its signed assertion changed after signing, so that the signature of the assertion no longer holds |
| `response-signed-response-signed-assertion-changed.data.xml` | the same changed assertion under the template of the signature of the response |
| `response-not-an-assertion.data.xml` | the response in clear, its `ID` changed to `_response-inside`, inside the `saml:EncryptedAssertion` in place of the assertion |
| `response-signed-assertion-signed-response.data.xml` | the signed assertion of the first, the response carrying the template of the third: what Entra's "Sign SAML response and assertion" sends |
| `response-signed-response-not-an-assertion.data.xml` | the fourth under the template of the response's signature |
| `response-signed-response-assertion-of-another-issuer.data.xml` | the second, its assertion's `Issuer` `https://other.example.com/saml`, under that template |

`encrypted-data-aes256-gcm.template.xml` is the template of `tests/xml-security/Enc/Fixture/vectors/`: `aes256-gcm`
for the content, the session key under `rsa-oaep-mgf1p`, the certificate in the `KeyInfo` of the `EncryptedKey`, a hint
the validator never reads (enc.md E-6).

## The vectors

From `tests/saml2-model/Fixture/`, the script below in a file `xmlsec.sh` next to it:

```
docker run --rm -v "$PWD:/w" -w /w alpine:3.22 sh xmlsec.sh
```

```
set -e
apk add -q xmlsec
ENC="xmlsec1 --encrypt --lax-key-search --pubkey-cert-pem keys/sp-signing-certificate.pem --session-key aes-256-gcm"
ID="--id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --node-id _assertion"
$ENC $ID --xml-data encrypted/response-signed-assertion.data.xml \
    --output encrypted/response-encrypted-signed-assertion-accepted.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-unsigned-assertion.data.xml \
    --output encrypted/response-encrypted-unsigned-assertion-refused.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-signed-response.data.xml \
    --output /tmp/response-signed-response.encrypted.xml encrypted/encrypted-data-aes256-gcm.template.xml
xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-signing-key.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
    --output encrypted/response-signed-over-encrypted-assertion-accepted.xml /tmp/response-signed-response.encrypted.xml
$ENC --node-xpath "/*/*[local-name()='EncryptedAssertion']/*" --xml-data encrypted/response-not-an-assertion.data.xml \
    --output encrypted/response-encrypted-not-an-assertion-refused.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-signed-assertion-changed.data.xml \
    --output encrypted/response-encrypted-assertion-changed-after-signing-refused.xml encrypted/encrypted-data-aes256-gcm.template.xml
$ENC $ID --xml-data encrypted/response-signed-response-signed-assertion-changed.data.xml \
    --output /tmp/response-signed-response-changed.encrypted.xml encrypted/encrypted-data-aes256-gcm.template.xml
xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-signing-key.pem \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
    --output encrypted/response-signed-over-encrypted-assertion-changed-after-signing-refused.xml \
    /tmp/response-signed-response-changed.encrypted.xml
```

And the checks, in the same container: xmlsec1 decrypts each vector to the bytes of its data file, and verifies the
signature of the response over the ciphertext.

```
DEC="xmlsec1 --decrypt --lax-key-search --privkey-pem keys/sp-signing-key.pem"
$DEC --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    encrypted/response-encrypted-signed-assertion-accepted.xml | diff encrypted/response-signed-assertion.data.xml -
$DEC encrypted/response-encrypted-unsigned-assertion-refused.xml | diff encrypted/response-unsigned-assertion.data.xml -
$DEC encrypted/response-encrypted-not-an-assertion-refused.xml | diff encrypted/response-not-an-assertion.data.xml -
$DEC --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    encrypted/response-encrypted-assertion-changed-after-signing-refused.xml \
    | diff encrypted/response-signed-assertion-changed.data.xml -
for f in response-signed-over-encrypted-assertion-accepted.xml \
    response-signed-over-encrypted-assertion-changed-after-signing-refused.xml; do
    xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/idp-signing-certificate.pem \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response "encrypted/$f"
done
```

The vectors of the changed assertion were written on 22 October 2026 too, after the others, by their own commands
above; xmlsec1 refuses the signature of the assertion they decrypt to (`REFERENCE`), as the validator does.

The session key and the IV are drawn at every run, so a run writes other ciphertexts: the committed vectors are those
of 22 October 2026.

| Vector | Serves |
|---|---|
| `response-encrypted-signed-assertion-accepted.xml` | §9.3 row 23: read with the key of the service provider as the same assertion in clear |
| `response-signed-over-encrypted-assertion-accepted.xml` | §9.3 row 24: the assertion without a signature, covered by the response's over its ciphertext |
| `response-encrypted-unsigned-assertion-refused.xml` | §9.2 row 40: nothing covers the assertion, `SignatureRequired` |
| `response-encrypted-not-an-assertion-refused.xml` | §9.2 row 41: the plaintext is a `samlp:Response` |
| `response-encrypted-assertion-changed-after-signing-refused.xml` | §9.2 row 46: the assertion's own signature fails once decrypted, `DigestMismatch` |
| `response-signed-over-encrypted-assertion-changed-after-signing-refused.xml` | §9.2 row 46: the same under a response whose signature over the ciphertext holds |

## The hostile fixtures

`derive.php`, run from this directory once the vectors are written, each replacement refused unless the text it
replaces is found exactly once:

```
php derive.php hostile
```

| Fixture | Made from | Serves |
|---|---|---|
| `response-encrypted-ciphertext-altered-refused.xml` | the first vector, the first byte of the ciphertext, right after the IV, flipped | §9.2 row 38, `DecryptionFailed` |
| `response-encrypted-tag-truncated-refused.xml` | the first vector, the last byte of the cipher value cut, so that the tag is 15 bytes and the last 16 do not verify | §9.2 row 38, `DecryptionFailed` |
| `response-signed-over-encrypted-assertion-ciphertext-altered-refused.xml` | the signed vector, the same byte flipped | §9.2 row 39, `DigestMismatch` before any decryption |
| `response-encrypted-without-issuer-refused.xml` | the first vector without the `Issuer` of the response | §9.2 row 42, E17, refused at step 2 |
| `response-encrypted-assertion-empty-refused.xml`, `response-encrypted-assertion-two-encrypted-data-refused.xml` | the first vector, its `saml:EncryptedAssertion` emptied, then holding its `xenc:EncryptedData` twice | §9.2 row 43 |
| `response-encrypted-two-encrypted-assertions-refused.xml` | the first vector, its `saml:EncryptedAssertion` twice | §9.2 row 43 |
| `response-encrypted-next-to-an-assertion-refused.xml` | the first vector, the signed assertion in clear of `../behaviour/response-signed-assertion-accepted.xml` after its `saml:EncryptedAssertion` | §9.2 row 43 |
| `response-encrypted-in-a-failure-refused.xml` | the first vector, its status `Responder` | §9.2 row 43 |
| `response-encrypted-key-as-a-sibling-refused.xml` | the first vector, its `xenc:EncryptedKey` moved out of the `ds:KeyInfo`, next to the `xenc:EncryptedData` | §9.2 row 44 |

The third case of row 38, the wrong key, needs no fixture: the first vector read with the test key of the identity
provider.

## AES-CBC

The responses whose assertion is encrypted under AES-CBC, which the validator reads only under the signature of the
response (section 6.7, enc.md E-15; rows 47 and 48 of section 9.2, row 25 of section 9.3), made on 22 October 2026 by
the same xmlsec1, for the same keys, in three runs: xmlsec1 encrypts, `derive.php` alters two ciphertexts, and xmlsec1
signs the responses over the ciphertexts as they then are, so that the signature holds over an altered one.
`encrypted-data-aes128-cbc.template.xml` names `aes128-cbc` under `rsa-oaep-mgf1p`, the shape SimpleSAMLphp's library
writes; `encrypted-data-aes256-cbc-mgf1p-digest-sha1.template.xml` names `aes256-cbc` under `rsa-oaep-mgf1p` with the
`DigestMethod` of SHA-1, the shape Entra and ADFS write.

The first run, from `tests/saml2-model/Fixture/`, the script in a file `encrypt.sh` next to it
(`docker run --rm -v "$PWD:/w" -w /w alpine:3.22 sh encrypt.sh`), checks that xmlsec1 decrypts each output back to
its data file, the empty elements of the template of the signature written in their short form:

```
set -e
apk add -q xmlsec
ID="--id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --node-id _assertion"
CBC128="xmlsec1 --encrypt --lax-key-search --pubkey-cert-pem keys/sp-signing-certificate.pem --session-key aes-128-cbc $ID"
CBC256="xmlsec1 --encrypt --lax-key-search --pubkey-cert-pem keys/sp-signing-certificate.pem --session-key aes-256-cbc $ID"
$CBC128 --xml-data encrypted/response-unsigned-assertion.data.xml \
    --output encrypted/response-encrypted-aes128-cbc-unsigned-assertion-refused.xml encrypted/encrypted-data-aes128-cbc.template.xml
$CBC256 --xml-data encrypted/response-signed-assertion.data.xml \
    --output encrypted/response-encrypted-aes256-cbc-signed-assertion-refused.xml \
    encrypted/encrypted-data-aes256-cbc-mgf1p-digest-sha1.template.xml
$CBC128 --xml-data encrypted/response-signed-assertion-signed-response.data.xml \
    --output encrypted/cbc-aes128.tmp.xml encrypted/encrypted-data-aes128-cbc.template.xml
$CBC256 --xml-data encrypted/response-signed-assertion-signed-response.data.xml \
    --output encrypted/cbc-aes256.tmp.xml encrypted/encrypted-data-aes256-cbc-mgf1p-digest-sha1.template.xml
DEC="xmlsec1 --decrypt --lax-key-search --privkey-pem keys/sp-signing-key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
$DEC encrypted/response-encrypted-aes128-cbc-unsigned-assertion-refused.xml | diff encrypted/response-unsigned-assertion.data.xml -
$DEC encrypted/response-encrypted-aes256-cbc-signed-assertion-refused.xml | diff encrypted/response-signed-assertion.data.xml -
EMPTY="s#<ds:DigestValue></ds:DigestValue>#<ds:DigestValue/>#;s#<ds:SignatureValue></ds:SignatureValue>#<ds:SignatureValue/>#"
sed "$EMPTY" encrypted/response-signed-assertion-signed-response.data.xml > /tmp/data.xml
for v in aes128 aes256; do
    $DEC encrypted/cbc-$v.tmp.xml | diff /tmp/data.xml -
done
```

The second, `php derive.php cbc` in this directory, writes `cbc-aes128-padding-altered.tmp.xml` and
`cbc-aes128-first-block-altered.tmp.xml` from `cbc-aes128.tmp.xml`, and the response whose valid signature is over
another element, from the unsigned one of the first run. The third, the script in a file `sign.sh`, signs and verifies:

```
set -e
apk add -q xmlsec
SIGN="xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-signing-key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response"
$SIGN --output encrypted/response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml encrypted/cbc-aes128.tmp.xml
$SIGN --output encrypted/response-signed-over-encrypted-assertion-aes256-cbc-accepted.xml encrypted/cbc-aes256.tmp.xml
$SIGN --output encrypted/response-signed-over-encrypted-assertion-aes128-cbc-padding-altered-refused.xml \
    encrypted/cbc-aes128-padding-altered.tmp.xml
$SIGN --output encrypted/response-signed-over-encrypted-assertion-aes128-cbc-first-block-altered-refused.xml \
    encrypted/cbc-aes128-first-block-altered.tmp.xml
VERIFY="xmlsec1 --verify --lax-key-search --pubkey-cert-pem keys/idp-signing-certificate.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response"
for f in aes128-cbc-accepted aes256-cbc-accepted aes128-cbc-padding-altered-refused aes128-cbc-first-block-altered-refused; do
    $VERIFY encrypted/response-signed-over-encrypted-assertion-$f.xml
done
rm encrypted/*.tmp.xml
```

| Fixture | Made from | Serves |
|---|---|---|
| `response-signed-over-encrypted-assertion-aes128-cbc-accepted.xml`, `response-signed-over-encrypted-assertion-aes256-cbc-accepted.xml` | the signed assertion and the signed response, `aes128-cbc`, then `aes256-cbc` with the `DigestMethod` of SHA-1 | §9.3 row 25: read as the assertion in clear |
| `response-encrypted-aes128-cbc-unsigned-assertion-refused.xml` | the unsigned assertion, the response unsigned | §9.2 row 47: no signature at all |
| `response-encrypted-aes256-cbc-signed-assertion-refused.xml` | the signed assertion, the response unsigned | §9.2 row 47: the assertion's signature, inside the ciphertext |
| `response-encrypted-aes128-cbc-signature-in-extensions-refused.xml` | the unsigned one, the signed assertion in clear of `../behaviour/response-signed-assertion-accepted.xml` inside a `samlp:Extensions` after its `Issuer` | §9.2 row 47: a valid signature of the identity provider over another element |
| `response-signed-over-encrypted-assertion-aes128-cbc-padding-altered-refused.xml` | the last octet of the block before the last XORed with `0x80` before the signature, the count of the padding out of range | §9.2 row 48 |
| `response-signed-over-encrypted-assertion-aes128-cbc-first-block-altered-refused.xml` | the first octet of the ciphertext flipped before the signature, the first block garbled and the count left | §9.2 row 48 |

The third case of row 48, the wrong key, needs no fixture: the first `aes128-cbc` response read with the test key of the
identity provider.

## The key given with each identity provider, and the reading after a CBC decryption

Made on 22 October 2026 by the same xmlsec1, after the review of the pull request (section 5.5, §9.2 rows 49 to 51).
`php derive.php data` writes the two data files above; `php derive.php hostile` writes
`response-signed-over-encrypted-assertion-aes128-cbc-ciphertext-altered-after-signing-refused.xml`, the first byte of
the ciphertext of the signed `aes128-cbc` response flipped after its signature (row 50); `php derive.php foreign` takes
that response, intact, its signature replaced by the template and its `Issuer` by `https://idp-b.example.com/saml`, into
`cbc-aes128-signed-by-b.tmp.xml`. Then, from `tests/saml2-model/Fixture/`, the script in a file `more.sh`:

```
set -e
apk add -q xmlsec
ID="--id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --node-id _assertion"
CBC128="xmlsec1 --encrypt --lax-key-search --pubkey-cert-pem keys/sp-signing-certificate.pem --session-key aes-128-cbc"
$CBC128 --node-xpath "/*/*[local-name()='EncryptedAssertion']/*" \
    --xml-data encrypted/response-signed-response-not-an-assertion.data.xml \
    --output encrypted/cbc-aes128-not-an-assertion.tmp.xml encrypted/encrypted-data-aes128-cbc.template.xml
$CBC128 $ID --xml-data encrypted/response-signed-response-signed-assertion-changed.data.xml \
    --output encrypted/cbc-aes128-assertion-changed.tmp.xml encrypted/encrypted-data-aes128-cbc.template.xml
$CBC128 $ID --xml-data encrypted/response-signed-response-assertion-of-another-issuer.data.xml \
    --output encrypted/cbc-aes128-another-issuer.tmp.xml encrypted/encrypted-data-aes128-cbc.template.xml
RESPONSE="--id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response"
SIGN="xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-signing-key.pem $RESPONSE"
$SIGN --output encrypted/response-signed-over-encrypted-aes128-cbc-not-an-assertion-refused.xml \
    encrypted/cbc-aes128-not-an-assertion.tmp.xml
$SIGN --output encrypted/response-signed-over-encrypted-aes128-cbc-assertion-changed-after-signing-refused.xml \
    encrypted/cbc-aes128-assertion-changed.tmp.xml
$SIGN --output encrypted/response-signed-over-encrypted-aes128-cbc-assertion-of-another-issuer-refused.xml \
    encrypted/cbc-aes128-another-issuer.tmp.xml
xmlsec1 --sign --lax-key-search --privkey-pem keys/idp-b-signing-key.pem $RESPONSE \
    --output encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml \
    encrypted/cbc-aes128-signed-by-b.tmp.xml
VERIFY="xmlsec1 --verify --lax-key-search $RESPONSE"
for f in not-an-assertion assertion-changed-after-signing assertion-of-another-issuer; do
    $VERIFY --pubkey-cert-pem keys/idp-signing-certificate.pem encrypted/response-signed-over-encrypted-aes128-cbc-$f-refused.xml
done
$VERIFY --pubkey-cert-pem keys/idp-b-signing-certificate.pem \
    encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml
DEC="xmlsec1 --decrypt --lax-key-search --privkey-pem keys/sp-signing-key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
$DEC encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml > /dev/null
if xmlsec1 --decrypt --lax-key-search --privkey-pem keys/sp-b-encryption-key.pem \
    encrypted/response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml > /dev/null 2>&1; then exit 1; fi
rm encrypted/*.tmp.xml
```

xmlsec1 verifies each signature under its signer's certificate; the ciphertext the second provider carries opens under
the key of the first and not under the key given with the second.

| Fixture | Made from | Serves |
|---|---|---|
| `response-aes128-cbc-ciphertext-of-another-provider-signed-by-b-refused.xml` | the signed `aes128-cbc` response of the first provider, its ciphertext intact, signed again by the second (`../keys/idp-b-signing-key.pem`) under its own `Issuer` | §9.2 row 49: the key given with the second provider asked, and opening nothing |
| `response-signed-over-encrypted-assertion-aes128-cbc-ciphertext-altered-after-signing-refused.xml` | the signed `aes128-cbc` response, a byte of its ciphertext flipped after the signature | §9.2 row 50: `DigestMismatch`, the key never asked |
| `response-signed-over-encrypted-aes128-cbc-not-an-assertion-refused.xml`, `response-signed-over-encrypted-aes128-cbc-assertion-changed-after-signing-refused.xml`, `response-signed-over-encrypted-aes128-cbc-assertion-of-another-issuer-refused.xml` | the three data files encrypted under `aes128-cbc`, each response signed by the first provider | §9.2 row 51: the one failure of the decryption, whatever the reading refused |
