# Test keys

Key pairs for the tests of this package and nothing else: an identity provider pair and a service provider pair
(section 9.1 of `spec/model.md`). The private keys are public by construction, in this repository, and sign no real
document anywhere. Never trust either certificate outside the tests.

Each is an RSA-2048 key with a self-signed certificate valid ten years from its generation, PEM, made in Alpine 3.22.6
with OpenSSL 3.5.9 on 30 September 2026, from the directory of this file:

```
docker run --rm -v "$PWD:/keys" -w /keys alpine:3.22 sh -c 'apk add -q openssl \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout idp-signing-key.pem -out idp-signing-certificate.pem \
        -days 3650 -subj "/CN=saml2-model test identity provider key, not a secret" \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout sp-signing-key.pem -out sp-signing-certificate.pem \
        -days 3650 -subj "/CN=saml2-model test service provider key, not a secret"'
```

| File | Serves | Valid | SHA-256 fingerprint of the certificate |
|---|---|---|---|
| `idp-signing-key.pem`, `idp-signing-certificate.pem` | the identity provider: it signs responses, assertions, logout messages and its metadata; its certificate is the one the identity provider's metadata carries | 30 September 2026 to 27 September 2036 | `30:D1:2B:B2:5C:D7:74:63:30:E8:5A:A7:31:61:A5:02:1C:8B:0E:27:98:AD:B4:23:31:60:87:F1:90:C4:72:7B` |
| `sp-signing-key.pem`, `sp-signing-certificate.pem` | the service provider: it signs authentication requests, logout messages and its metadata; its certificate is the one the service provider's metadata carries | 30 September 2026 to 27 September 2036 | `52:48:FA:3C:DE:44:AE:D4:72:53:D8:D5:FB:1C:08:CE:7D:ED:0B:FF:57:26:34:3C:81:11:9C:12:B6:1A:1D:30` |

Two more, on 22 October 2026 with OpenSSL 3.5.9 in Alpine 3.22, for a second identity provider of the same service
provider (section 5.5 and §9.2 row 49 of `spec/model.md`): its signing pair, and the pair whose certificate the service
provider gave it to encrypt with, which no response of the first provider is encrypted for.

```
docker run --rm -v "$PWD:/keys" -w /keys alpine:3.22 sh -c 'apk add -q openssl \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout idp-b-signing-key.pem -out idp-b-signing-certificate.pem \
        -days 3650 -subj "/CN=saml2-model test second identity provider key, not a secret" \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout sp-b-encryption-key.pem -out sp-b-encryption-certificate.pem \
        -days 3650 -subj "/CN=saml2-model test key the SP gave the second IdP, not a secret"'
```

| File | Serves | Valid | SHA-256 fingerprint of the certificate |
|---|---|---|---|
| `idp-b-signing-key.pem`, `idp-b-signing-certificate.pem` | the second identity provider: it signs the response that carries the first provider's ciphertext | 22 October 2026 to 19 October 2036 | `09:1E:2F:34:DE:EF:77:1E:7F:B2:B3:54:CB:0E:C3:B1:2C:68:2A:CF:1D:5F:9C:43:1F:97:FF:E0:A2:DE:10:6F` |
| `sp-b-encryption-key.pem`, `sp-b-encryption-certificate.pem` | the key the service provider gives with the second identity provider, whose certificate went to it | 22 October 2026 to 19 October 2036 | `6A:AE:57:F7:3F:BB:39:2F:D6:1C:AF:CB:5F:AA:D3:33:36:56:D9:67:81:EE:74:24:9D:F5:13:0D:05:CD:5D:FE` |

The SimpleSAMLphp library of `tests/saml2-model/Interop/simplesamlphp/library/` signs its fixtures with these two pairs. The
SimpleSAMLphp installation of `tests/saml2-model/Interop/simplesamlphp/installation/` has pairs of its own, next to it.
