# Changelog

All notable changes to this project are documented in this file, in reverse chronological order by release.

## 0.2.0 - TBD

### Added

- Nothing.

### Changed

- `beffroi/core`: a username is prepared, enforced and compared by the UsernameCaseMapped profile of PRECIS (RFC 8265
  §3.3), which RFC 7644 §5 requires of a `userName`: `Alice`, `ALICE` and `alice`, a name in fullwidth letters and an
  `é` written with a combining accent are each one person. Letters and digits of every script and printable ASCII
  pass; a space, a symbol or a punctuation mark outside ASCII, an emoji, a code point with a compatibility equivalent
  and a username written right to left that breaks the Bidi Rule (RFC 5893 §2) are refused, by `UsernameRefusedException`,
  at the console, at the administration API (`400 invalid_request`) and at the first sign-in through an upstream
  provider alike, a later sign-in under such an address keeping the username of the person. The username is kept as
  it was written. The local part of an address is brought to Normalization
  Form C (RFC 6532 §3.1) before it is lowercased.
- `beffroi/beffroi`: the blind index of a username is its enforced form, and a lookup tries the username as written
  first, so that a person written by 0.1 is found under their username as written until the tags are derived again.
  The image derives them at its first start, after the migrations (`beffroi:user:reindex --when-due`), and again
  whenever what a tag derives changes, the version of Unicode of its intl included; a deployment that does not run the
  entrypoint of the image runs `bin/console beffroi:user:reindex` once after the upgrade. Until then no person is
  created or renamed: the console says why, the administration API answers `503 temporarily_unavailable`, and a first
  sign-in through an upstream provider is refused. The command names each person whose username the profile refuses,
  who signs in under it as written until an administrator renames them and at the latest until 1.0.0, and the persons
  whose usernames it compares as one, whom no lookup finds until they are renamed; it then exits with the status 3.
  `beffroi:user:rename` renames a person, and every console command that names a person takes their identifier as
  well as their username. `beffroi:doctor` says what the last reindex left.
- `beffroi/core`: a password is prepared and enforced by the OpaqueString profile of PRECIS (RFC 8265 §4.2), which RFC
  7644 §5 requires of a `password`, before it is hashed and before it is verified, at the console, on the page of the
  account, through a password ticket and at the sign-in: a no-break space or an ideographic space is a space, and a
  letter written with a combining accent is the composed one; case and width are kept. A password holding a control
  character, an ignorable code point (the variation selector U+FE0F that follows many emoji, the zero width joiner
  inside an emoji made of several), a code point Unicode does not assign or one of private use is refused, with
  `password.error.disallowed_character`. The breach lookup receives the enforced form.
- `beffroi/core`, **who is locked out**: a person whose password holds what the profile refuses no longer signs in with
  it, and cannot ask for a password ticket herself. Each refused sign-in is an act `authentication.failed` of her
  journal with the reason `disallowed_character` (`bin/console beffroi:user:journal <username>`, `GET
  /users/{id}/journal` of the administration API); an administrator gives her a password ticket
  (`bin/console beffroi:user:password-ticket <username>`, `POST /users/{id}/password-ticket`).
- `beffroi/beffroi`: a migration adds `beffroi_password_credential.hashed_as_typed`, true for every hash written before
  the profile. While a tenant holds one, every sign-in of the tenant verifies the enforced form and the bytes as typed
  when they differ, whatever the account, and the sign-in of such a person replaces her hash by one of the enforced
  form, ASCII included; once none is left, one form is verified. Meanwhile the time of a refused sign-in says only that
  the tenant still holds such a hash.
- `beffroi/core`: what a password may hold is derived from the Unicode version of the intl extension the process runs
  (RFC 8264 §13.4). A password set under a newer version can be refused by a process under an older one, during a
  rolling deployment, after a rollback, or at the console of a host whose PHP is not the image's: every process of a
  deployment runs the same image.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.

## 0.1.1 - TBD

### Added

- Nothing.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- `beffroi/beffroi`: an asynchronous message retried after a handler failure reads back, and is no longer sent to the
  failure transport as unrecoverable at its first retry. The moment the retry listener of Messenger stamps on it, a
  `DatePoint` of the clock of the component, is now read back from the headers of the transport with the stamp.
- `beffroi/beffroi`: a message the scheduler sends to an asynchronous transport is read back with its
  `ScheduledStamp`: every scheduled task went to the failure transport.
- `beffroi/beffroi`: a stamp header of a queued message that PHP cannot read back into its stamp, such as a string in
  a property typed `int`, is a stamp that does not read back like any other: the message keeps its other stamps and
  goes through the retry strategy of its transport, instead of going to the failure transport at once without them.
  A header of the `RedeliveryStamp`, which counts the retries, that does not read back sends the message to the
  failure transport at once, with its other stamps: retried without its count, it would be retried forever.

## 0.1.0 - 2026-11-26

The first release. `beffroi/core`, and every package that requires it, requires `symfony/key-management` 8.2, published
only as pre-releases until Symfony 8.2.0 is out: until then, a project that requires them sets
`"minimum-stability": "beta"` and `"prefer-stable": true` in its `composer.json`.

### Added

- `beffroi/beffroi`, the provider: an OAuth 2.0 authorization server, an OpenID Provider and a SAML 2.0 identity
  provider in one Symfony application on FrankenPHP, configured through its environment. Each release publishes it as
  the image `ghcr.io/beffroi-auth/beffroi`, for linux/amd64 and linux/arm64. Its server runs 4 threads of the provider
  and 2 of the administration API whatever the cores of the host, each holding one connection to the database, and
  `FRANKENPHP_WORKER_NUM` and `FRANKENPHP_ADMINISTRATION_WORKER_NUM` set them.
- `beffroi/core`, the identity model the provider owns: tenants, people with a stable `sub`, credentials, linked
  identities, groups, authentication sessions and keys.
- Passwords under typed hashes, passkeys, TOTP and backup codes, each a credential of its own; `amr` and `acr` on the
  ID token, and a step-up when a client asks for `acr_values`.
- `beffroi/oidc`, OAuth 2.0 and OpenID Connect: the authorization code grant with PKCE `S256`, refresh tokens,
  `client_credentials`, the device authorization grant (RFC 8628), CIBA in poll and ping modes, token exchange
  (RFC 8693) and the JWT bearer grant (RFC 7523); `at+jwt` access tokens (RFC 9068), UserInfo, introspection,
  revocation, discovery and the JWK Set.
- Pushed authorization requests (RFC 9126), request objects by value and by reference (RFC 9101), signed authorization
  responses (JARM), `form_post`, resource indicators (RFC 8707) and rich authorization requests (RFC 9396).
- Client authentication by `private_key_jwt` and `client_secret_jwt`, and tokens bound to a key by DPoP (RFC 9449).
  Mutual TLS client authentication and certificate-bound tokens (RFC 8705) are announced and served only when
  `BEFFROI_MTLS_ORIGIN` names the host that asks for the certificate, and `tls_client_auth` only when
  `BEFFROI_MTLS_CERTIFICATE_AUTHORITIES` names the authorities whose certificates it accepts, which the provider
  validates the certificate against when it is presented.
- RP-Initiated, Back-Channel and Front-Channel Logout.
- Dynamic client registration (RFC 7591, RFC 7592), controlled by initial access tokens; pairwise subjects and a login
  the provider begins at the client.
- Signing keys sealed through `symfony/key-management`, by Vault Transit, AWS KMS or a key file, and rotated without an
  outage.
- Personal data encrypted at rest under data keys of the tenant, with blind indexes for the lookups.
- `beffroi/saml`, SAML 2.0: the identity provider of a tenant, and its service provider toward an upstream identity
  provider, on `beffroi/saml2-bindings` (HTTP-Redirect and HTTP-POST), `beffroi/saml2-model` (messages, assertions and
  metadata) and `beffroi/xml-security` (a safe DOM, XML Signature and XML Encryption).
- The pages of a tenant and the account of a person, in 31 languages of Europe, every member state of the European
  Union in its national language: their sessions, the applications that hold something of them, the information they
  may change, the history of their record, and an archive of everything the provider holds about them.
- The administration API of an instance, served apart from its endpoints and its pages, and `beffroi/tui`, its terminal
  client. Each release carries the client as `beffroi-tui.phar` and as executables for Linux x86_64, Linux arm64 and
  macOS on Apple silicon, with `SHA256SUMS` and its signature.
- Every secret the image reads, the secret of the kernel, the database and the role that owns its tables, the key
  management service, the lanes, mail, SMS and the licence of the address databases, may be given as a file, its path
  in the variable of the same name ending in `_FILE`, where Swarm and Compose mount a secret; naming both is refused.
  gpg, the one program the provider starts, gets none of its environment.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.
