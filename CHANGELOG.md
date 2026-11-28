# Changelog

All notable changes to this project are documented in this file, in reverse chronological order by release.

## 0.2.0 - TBD

### Added

- Nothing.

### Changed

- `beffroi/core`: an act of the journal and a change of a claim name their author by one of five kinds (decision
  0066): the person, an administrator of the tenant by the subject of their account, a client by its identifier, a
  directory by its name, or the host. `NamesItsAuthorInterface::author()`, `JournalEntry::$author` and
  `ClaimChange::$author` hold an `AuthorInterface` in place of a `Subject`; `PersonCreation::create()`,
  `PersonDescription::describe()`, `PersonDisabling::disable()` and `PersonEnabling::enable()` take the author in place
  of their `…ByAnAdministrator()` twin, and `SessionTerminator::end()`, `CredentialRevocation::revoke()`,
  `ConsentRevocation::revoke()`, `RegisteredClientRemoval::remove()` and `OtherSessionsTermination::endEvery()` take the
  author their callers name. A token a client revokes (RFC 7009) names that client. Every session a disabling ends
  ends as an act of administration, the console's included.
- `beffroi/beffroi`: the journal of a person the administration API answers and `beffroi:user:journal --format=json`
  name the author of an act by its document, `{"kind": "administrator", "subject": "…"}` for instance, in place of the
  subject of an administrator, and the archive of a person names who made each act and each change by their kind, an
  administrator by that kind alone. The migration widens the two columns to text and rewrites no row, the journal and
  the history being chains whose head the provider signed; it refuses a database where one of them names an
  administrator by a subject that begins with `{`. A logout token or an event queued before the upgrade does not read
  back after it.

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
