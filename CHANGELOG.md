# Changelog

All notable changes to this project are documented in this file, in reverse chronological order by release.

## 0.2.0 - TBD

### Added

- Nothing.

### Changed

- `beffroi/core`: every act of the journal and every change of a claim names its author, of one of seven kinds
  (decision 0066): the person, an administrator of the tenant by the subject of their account, a client by its
  identifier, a directory or an upstream provider by the name the deployment declares it under, an unauthenticated
  caller, or the host. `DomainEventInterface` extends `NamesItsAuthorInterface`, whose `author()` returns an
  `AuthorInterface`; `JournalEntry::$author` and `ClaimChange::$author` hold one in place of a `Subject`, `null` only for
  an act written before acts named their author. `PersonCreation::create()`, `PersonDescription::describe()`,
  `PersonDisabling::disable()` and `PersonEnabling::enable()` take the author in place of their `…ByAnAdministrator()`
  twin, and `SessionTerminator::end()`, `CredentialRevocation::revoke()`, `ConsentRevocation::revoke()`,
  `RegisteredClientRemoval::remove()` and `OtherSessionsTermination::endEvery()` take the author their callers name.
  `JournalQuestion` and `ClaimChangeQuestion` narrow by the name of a kind (`$by`) in place of a boolean, and the wired
  kinds are listed by `KindsOfAuthorInterface`. `SessionEnd` says how a session ended: a console ending one ends it as
  an act of administration, as every disabling does, and another person signing in from the same browser ends it by
  the rule of the host (`Security`).
- `beffroi/beffroi`: the person reads who did each act and each change: an administrator and the host by their role,
  without the user of the shell or the name of the host a command records, a directory and an upstream provider by
  their name, the others by where the act came from, and the page of the acts and the page of the history narrow by the
  kind of the author. The archive of a person and the journal of the administration API name the author by an object,
  `{"kind": "administrator"}` in the archive, the whole document in the API and in `beffroi:user:journal --format=json`,
  where both gave a string: the TUI 0.2.0 or later reads it, and an older TUI refuses the journal of a person.
- `beffroi/beffroi`: the page of the acts and the archive of a person leave out the user agent of a request without an
  address, the console's or the schedule's, which names the command and the shell of the operator: an act written
  before acts named their author says nothing of the operator either. Once a kind of author is chosen, the page says
  that an act naming no author is listed only when none is.
- `beffroi/beffroi`, **upgrading**: stop the processes that dispatch messages, the planes of the provider, of the
  protocol and of the administration, then let the worker drain the four lanes, `async_priority_high`,
  `async_priority_medium`, `async_priority_low` and `async_notifications`, the logout tokens whose issue it retries
  later included, and empty the failure transport (`messenger:failed:retry` or `messenger:failed:remove`); then deploy.
  A body the version before queued is read back nonetheless, naming the administrator it named, and one no class of
  this release can build goes to the failure transport instead of stopping the worker. The migration widens two
  columns and rewrites no row, the journal and the history being chains whose head the provider signed; it refuses a
  database where one of them names an administrator by a subject that begins with `{`, and says how to rewrite those
  rows. **The upgrade goes one way** once an act is written: the image of the version before reads the author of every
  act written since as the subject of an administrator, and only a backup of the database taken before the migration
  goes back.

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
