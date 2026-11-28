# scim: specification

The SCIM 2.0 module of the identity provider: the service provider of RFC 7643 and RFC 7644 for the directories a deployment declares, which push the persons and the groups of a tenant to it. It holds what the protocol asks of a service provider, the HTTP request aside, which is the application's: the token of a directory, the mapping of the `User` and `Group` schemas and of the `EnterpriseUser` extension onto the identity model of the core and onto the record a directory keeps of a person, the filter, the pagination, the versioning and the errors of the protocol, and what the provider announces of itself.

| | |
|---|---|
| Repository | `src/scim` of the monorepo `beffroi-auth/beffroi`, mirrored read only into `beffroi-auth/scim` (section 10) |
| Package | `beffroi/scim` |
| Namespace | `Beffroi\Scim`, next to `Beffroi\Oidc` of `beffroi/oidc` and `Beffroi\Saml` of `beffroi/saml` |
| Runtime | PHP 8.4 or later; `beffroi/core`, its use cases included; the `intl` extension of PHP, for the normalization of Unicode, and `mbstring`, for its full case folding, which a comparison goes through (section 6.7). Nothing else: the JSON reader is PHP's, behind a reader of the bytes of the package's own (P-5), and no brick of `docs/09-briques.md` is the module's own. |
| Consumers | The application `beffroi/beffroi` (`apps/beffroi`), which holds the HTTP request, the routes, the console, the tables and the migrations (decision 0007) |
| Design | Spike 10 (epic beffroi-auth/beffroi#84); decisions 0002 (the provider owns its identity model, a directory being one more source of it), 0063 (a directory sees and writes only what it created), 0064 (a deletion is soft, then purged), 0065 (a username compared by PRECIS), 0066 (the author of an act), 0067 (the provider follows the specifications and names what a peer asks beyond them), 0011 (personal data sealed, the filter its named exception), 0014 (the load budgets of an origin and of a directory), 0022 (a read that returns a person is an act), 0039 (the tenant is an origin), 0006 (no option to do it wrong) |

This document states what the package does, what it refuses and what it guarantees; the code conforms to it, or the document changes first, in its own commit, with its reason. Its invariants are numbered `P-n`, and its sections bear the numbers of the specifications of the SAML packages. Every rule is written before the code that applies it: the stories of section 12 build them, each test citing the rule it verifies (section 9).

## 1. Why this package exists

The core holds a person, the groups of a tenant and the source of each (decision 0002). Federation creates a person at their first sign-in through an upstream provider; SCIM creates them before it, keeps them in step with the directory of the organisation, and deactivates them the day they leave. A directory speaks HTTP and JSON, and its resources are not the identity model: a `User` carries several typed addresses, a manager, a cost centre and a password, where the core holds one address, one phone number, one postal address and the claims of OIDC Core §5.1.

This package is the protocol and the translation between the two, so that a directory is one more source of the provenance model (decision 0063) and not a second model: what the identity model holds goes to the core, what it cannot hold is kept as the directory wrote it, sealed, in a record of that directory (section 6.3), and every claim takes one value of it by a rule written here (section 6.6).

## 2. Position

```mermaid
graph LR
    app["beffroi/beffroi<br/>Request, routes, console,<br/>tables"] --> scim["<b>beffroi/scim</b><br/>this package"]
    app --> oidc["beffroi/oidc"]
    app --> saml["beffroi/saml"]
    scim --> core["beffroi/core"]
    oidc --> core
    saml --> core
```

The package is a module of the identity provider, at the level of `beffroi/oidc` and `beffroi/saml`, and takes their four layers (`docs/11-architecture/README.md` section 2): `Domain`, the objects, the values and the exceptions (`Exception/` belongs to it, as in the core and the other modules); `Port`, the interfaces to the outside; `Application`, the use cases; `Bridge`, the implementations of the ports. It depends on the core, its use cases included, and never on `beffroi/oidc` nor on `beffroi/saml`, nor they on it: protocols never depend on each other. The core depends on none of the three.

It knows no HTTP object (decision 0007): no `Request`, no PSR-7 message, no superglobal, no route. The application reads the request and hands the package what section 5 names, the token presented, the method, the identifier of the path, the parameters of the query, the conditional headers and the bytes of the body; it writes the answer the package gives back, a status, its headers and a JSON document. The tables are the application's too: the resource table of the module (section 6.2), the record of a directory, which the core seals (section 6.3), and the digests of the tokens (P-1) are ports of the package, which the application implements on Doctrine.

Deptrac holds the layers and the graph, `.ci-tools/deptrac.yaml`: the `Scim*` layers see the layers of the core, the PSR interfaces, `psr/clock` and the `Uid` component of Symfony, as the `Oidc*` and `Saml*` layers do; nothing else of Symfony, nothing of `Psr\Http`, nothing of Doctrine, nothing of another module. No layer of the core and no layer of another module sees a `Scim*` layer.

## 3. Threat model

Each row is an attack class this package answers, the rule that answers it, and where the rule lives; the invariants are numbered in section 4. The last rows are what a rule leaves, said as such.

| Threat | Vector | Rule | Where |
|---|---|---|---|
| A stolen or guessed token writes every person of a directory | The value of a token read in a table, a log, a backup; a value guessed | 256 bits drawn by `random_bytes()`, shown once, its SHA-256 digest kept and compared by `hash_equals()`; an expiry it always has, a year at most; revocation | P-1, RFC 7644 §7.4 |
| A token outlives its directory | A revoked or expired token, or one of a directory the environment no longer declares | Verified at every request against its expiry, its revocation and the declaration of its directory | P-1 |
| A token carried to another tenant | The token of tenant A presented at the origin of tenant B, past an allowlist of the host of B | The tenant of a request is the one its origin serves; a token of another tenant answers `401` | P-1, decision 0039, RFC 7644 §6.1 |
| A directory takes over a person of another source | `userName eq` on the username of the emergency account of the administrator, then a `PUT`; the address of a local person pushed on a new one | A directory sees and writes only what it created; a username, an address or a group name another person or group holds answers `409 uniqueness` and nothing more | P-2, decision 0063 |
| A directory reads a person it did not create | An `id` of another directory or of a local person guessed or replayed | The `id` is drawn by the module per resource; any other answers `404`, the same answer as an `id` nobody holds | P-2, P-3 |
| A directory makes a relying party trust an address it does not hold | An address of another organisation pushed with `email_verified` expected | An address is verified only when its domain is, whole, one the deployment declares for that directory | P-10, decision 0063 |
| A directory sends the notices of decision 0049 to a number it chose | A phone number pushed for a person | A pushed number is never verified until the person confirms it, and no confirmation is sent unless the person asks | P-10, decision 0063 |
| A password guessed through the filter | `password eq "..."` repeated outside the guessing limit of decision 0014 | `password` is never a filter attribute, under any spelling of its name | P-8, P-21, decision 0067 |
| A sealed attribute read through a filter that returns nobody | `id eq "…" and phoneNumbers.value sw "+3361"` with `count=0`, `totalResults` read, the value found by bisection; a `replace` whose value path answers `noTarget`; a `remove` whose value path matches nothing and silently changes nothing | Each person a filter matches on more than an identifier is an act, returned or not, and so is the person a `PATCH` decided a value path on and found nothing | P-11, decision 0022 |
| A password leaks | Returned in an answer, kept in the record, written to a log or echoed in an error | Prepared and hashed by the core, `returned: never`, never in the record, in a log, an event or the `detail` of an error | P-8, P-19, RFC 7643 §4.1.1, §9.2 |
| A value leaks through a refusal | The message of an exception of the core, which names what it refused (`EmailAddress`), copied into `detail` or logged at an unmapped error | `detail` written from the rule, never from a message; every refusal of the core mapped; anything else a `500` that says nothing | P-19 |
| A boolean read wrong | `"active": "False"`, which a cast in PHP reads as true | A boolean is the JSON literal `true` or `false`, anything else refused | P-6, decision 0006 |
| A group emptied by a request read loosely | A `remove` on `members` that carries a `value`, read as a `remove` of the whole attribute | A `remove` that carries a `value` is refused | P-7 |
| An attribute named so that a check misses it | `paſſword` or a KELVIN SIGN folded onto a name; `urn:ietf:params:scim:schemas:core:2.0:User:password`; `userName` beside its URN form, `name` beside `name.givenName`, `op` twice in one operation | A name is US-ASCII, folded by ASCII only, resolved to its attribute before any rule applies; two names that resolve to one attribute, and a name written twice, refused | P-5, P-21 |
| The provider exhausted by a filter or a path | A filter or a `path` of a megabyte, nested a thousand times, of ten thousand terms; an operator no index serves on a directory of a million persons | Every filter and every path counted before it is read; the candidates a filter opens counted before one is opened, opened one at a time, `tooMany` past the bound | P-5, P-12, section 7 |
| The provider exhausted by a body | A body whose decoding builds fifty times its size, nested to the stack, with a hundred thousand members, or a name twice | A reader of the bytes, linear and in constant memory, counts the nesting, the values and the lists before `json_decode()` builds anything | P-5, section 7 |
| A resource grown past every bound | An `add` repeated on one attribute, certificates of 8 KiB a hundred times, a page of a hundred such persons, a group of a hundred thousand members in a page | The bounds of a request hold for the resource after the write; the record of a person and the members an answer carries are bounded | P-5, P-9, section 7 |
| Text that drives a terminal | An escape sequence or a bidirectional override in a value the record keeps, shown by `beffroi:user:show`, the TUI or the administration API | Every string of the record is plain text as the core holds a value; a URL it keeps is shown as text | P-9 |
| Personal data read in clear in the database | A filter answered by a `LIKE` or an `ORDER BY` on a sealed column | Nothing of a filter is written in clear, searched or sorted in the database but the columns kept in clear; the other operators are evaluated in memory | P-12, decision 0011 |
| Personal data in a log | A filter in the query string, a body logged on an error | The access log keeps the names of the parameters and never their values; nothing of a body is logged | P-20, RFC 7644 §7.5.2 |
| A lost update | Two writes on one resource, conditional or not, the second built on what the first replaced | The comparison of `If-Match` and the raise of the version in one statement; every write to one resource holds a lock on it | P-14, RFC 7644 §3.14 |
| A duplicate person, or one address verified twice | Two creations of one username or of one address racing, or a creation and a local registration of one address; one membership written twice at once | A unique constraint for a username and a group name, a lock on the blind index of an address, a unique constraint for a membership | P-14 |
| The administration taken by a directory | A group created before the tenant under a name `BEFFROI_TENANT_ADMINISTRATORS` lists | A group a directory holds administers the tenant only when the deployment names it with its directory | P-18, decision 0038 |
| A deleted resource comes back | A deleted `id` replayed, or a person restored by an administrator still written by the directory | `404` for every operation on a deleted resource, for good | P-15, RFC 7644 §3.6, decision 0064 |
| A deactivated person keeps signing in | `active: false` written while sessions and tokens live | The person disabled through the core, the sessions ended, the refresh tokens and the opaque access tokens revoked | P-16 |
| The record handed to a relying party | A claim, the UserInfo endpoint, an ID token built from what a directory wrote beyond the model | The record is read by SCIM, the archive and the administration only, never by a client | P-9 |
| **Left**: a stolen token is worth every person of its directory | The token sets the password of each of its persons and moves each address inside the domains of the directory, verified; when the deployment names one of its groups in `BEFFROI_TENANT_ADMINISTRATORS`, the administration of the tenant | Nothing of the protocol tells the directory from the holder of its token: the token is kept as a secret of that worth, expires, is revoked, spends one budget; each password set and each address or number moved is told to the person, at the previous channel too (decision 0049, beffroi-auth/beffroi#1451) | P-1, P-8, P-10, P-18 |
| **Left**: the journal grows with the reads | A first synchronisation reads every person, each one an act, and a directory that reads its pages again writes them again; a filter with `count=0` on an attribute evaluated in memory writes up to 1 000 acts, one per candidate it matches, in one request | The load budget of the directory bounds the requests; no budget of persons applies to a directory (decision 0063); the journal keeps its rows for its retention (decision 0022) | P-11, section 7 |
| **Left**: an address taken is an address told | A directory creates a person with an address to learn, from a `409`, that another person of the tenant holds it | Decision 0063 refuses a directory an address another person holds, which RFC 7643 does not ask: the `409` says that it is taken and nothing of who holds it | P-2, decision 0063 |
| **Left**: an emergency disabling lasts until the next push | An administrator disables a person of a directory locally; the directory writes `"active": true` again, as Okta's routine `PUT` of a profile does | The directory wins (decision 0002): to cut a person off for good, disable them at the directory, or revoke the token of the directory, which the page for a CISO says (beffroi-auth/beffroi#1433) | P-16 |
| A directory moves a person's address and the person never learns it | A stolen token writes an address of its choice on a person, then resets the password through it | The change is told to every channel the person held, the previous address included | P-10, beffroi-auth/beffroi#1451 |
| **Left**: a password costs at each push | A directory pushes the password a person already holds, or a new one, on every write; Okta sends a `password` in every creation of a person, even when it does not synchronise passwords, so every person it creates gets a password nobody chose, a notice of decision 0049 and a lookup in the breached passwords | A verification of the hash for the same password, a verification and a hash for another, at the rate the load budget of the directory allows | P-8, section 7 |
| **Left**: a name that looks like another | A directory creates a username shaped like an address of another directory, or with a Cyrillic letter beside a Latin one | Uniqueness and PRECIS compare what is written, not what it looks like; confusable characters are beffroi-auth/beffroi#1439 | P-2, decision 0065 |

## 4. Invariants

Each invariant is code, never a constructor option or a flag, has at least one test in section 9, and names the attack class it closes.

- **P-1. A directory authenticates by a token of its own, at its own tenant.** The token is presented as `Authorization: Bearer` (RFC 6750 §2.1), the scheme read without case (RFC 9110 §11.1), never in a form body (RFC 6750 §2.2) nor in the query (§2.3). Any other request, anonymous (RFC 7644 §2.2), Basic or carrying a token that is not valid, answers `401` with `WWW-Authenticate: Bearer realm="scim"` (RFC 6750 §3: the scheme « MUST be followed by one or more auth-param values »; RFC 7644 §2), with `error="invalid_token"` when it carried a bearer token, the same for a token revoked, expired or unknown (RFC 6750 §3.1), on every route of the module but `/ServiceProviderConfig`, which answers without a token (section 6.13). The value is 32 bytes of `random_bytes()`, written in base64url without padding (RFC 4648 §5): RFC 7644 §7.4 asks a bearer token for the entropy that resists guessing. It is shown once, at issuance; the provider keeps its SHA-256 digest only, looks the token up by that digest and compares it with `hash_equals()`. A token names one directory of one tenant; the tenant of a request is the one its origin serves (decision 0039), and a token of another tenant answers `401` as an unknown one does, so that no token reaches a tenant through the host of another (RFC 7644 §6.1: « The service provider should consider precedence in cases where a client may explicitly specify a Tenant while being implicitly associated with a different Tenant »). It expires (RFC 7644 §7.4: a bearer token MUST have a limited lifetime): a year by default and at most, a lifetime the issuer sets and never omits (decision 0063); a shorter one is accepted, a longer one refused, the default being the ceiling (decision 0006). A revoked token, an expired one, and one whose directory the environment no longer declares answer `401`. The value is in no table, no log, no answer but the one that issues it, and no event. A stolen or guessed token; a token carried to another tenant.
- **P-2. A directory sees and writes only what it created** (decision 0063). A person or a group of another source, local, federated, mapped or of another directory, does not exist for it: its `id` answers `404`, the same answer as an `id` no resource holds, and no query returns it. A username, an address or a group name another person or group holds answers `409` with `scimType` `uniqueness` (RFC 7644 §3.3, §3.12), and the answer says nothing else of who holds it: that a name is taken is all a directory learns. The address that counts is the one the `email` claim of the person takes (section 6.6), checked again whenever a write changes which value it takes: an address a person of a directory holds is held by no other person, of that directory or of any source, two local persons alone being free to share one (decision 0011). The `409` on a username is the uniqueness RFC 7643 §4.1.1 asks; the `409` on an address is decision 0063's choice, and what it tells is written in section 3. A takeover, and the reading of what a directory did not push.
- **P-3. The `id` is the module's.** It is drawn at random by the module for each resource, 122 random bits written as a UUID of version 4, stable across every write, never given to another resource, and never the identifier of the core, the `sub` of the person nor their `externalId` (RFC 7643 §3.1: issued by the service provider, unique across all of its resources, stable, non-reassignable). An `id` a client sends in a `POST` or a `PUT` is ignored (RFC 7643 §3.1, RFC 7644 §3.3, §3.5.1). An `id` guessed from another one.
- **P-4. The `sub` is drawn opaque** when a directory creates a person, never taken from `externalId`, `userName` or anything the directory sends (decision 0063). A `sub` chosen by a directory, the same at two tenants.
- **P-5. A request is counted before it is decoded.** First its body by its bytes; then a reader of those bytes, one pass, linear and in constant memory, before `json_decode()` builds anything: it counts the nesting, the values of the whole body, the elements of each array and the members across the operations of a `PATCH`, and refuses a name one object holds twice, which `json_decode()` would reduce to the last one (RFC 7644 §3.5.2: an operation « MUST have exactly one "op" member »; RFC 8259 §4: the names of an object SHOULD be unique). It compares two names once their escapes are decoded, as RFC 7493 §2.3 defines a duplicate (« after processing any escaped characters »), so that `{"op":"add","\u006fp":"remove"}` holds `op` twice. `json_decode()` reads only what that reader let through, with a depth one above the nesting allowed, which is how it counts levels. The names of `attributes` and `excludedAttributes`, the filter of a query, and the `path` of every operation of a `PATCH` with its value filter, are counted by their length, their nesting and their terms before they are parsed. The resource after a write is held to the bounds of a request: an `add` repeated does not grow an attribute past them (section 7). An exhaustion of the process.
- **P-6. A value has the JSON type of its attribute.** A boolean is the literal `true` or `false` (RFC 7643 §2.3.2), an integer a number with no fraction nor exponent (§2.3.4), a string a string, a complex value an object and a multi-valued one an array (§2.3.8, §2.4); anything else answers `400 invalidValue`, and nothing is cast (decision 0006). `"active": "False"` is refused, as decision 0067 names it. A value read as what it is not.
- **P-7. A `PATCH` says what it does.** Its `op` is `add`, `remove` or `replace`, written as RFC 7644 §3.5.2 writes them; `Replace` and any other value answer `400 invalidSyntax` (decision 0067). A `remove` names its target by its `path` (RFC 7644 §3.5.2.2), and one that carries a `value` answers `400 invalidSyntax`. That refusal is the provider's (decision 0006): RFC 6902 §4, on which the `PATCH` of SCIM is based (RFC 7644 §3.5.2), has a member an operation does not define ignored, and a `remove` of `members` read without its `value` empties the group. A destructive misreading.
- **P-8. A password is set, never read nor removed.** A `password` a directory pushes is prepared and enforced by the OpaqueString profile of PRECIS before it is hashed or compared (RFC 8265 §4.2, which RFC 7644 §5 requires of a `password`, beffroi-auth/beffroi#1442), then goes to the core (`UserProvisioner::setPassword()`), with its floor, its lookup in the breached passwords and the refusal of a federated domain (decision 0029), and is hashed there (RFC 7643 §9.2: never stored in cleartext). A password the person already holds changes nothing, at the cost of one verification of the hash; another one costs a verification and a hash, replaces it, ends every session of the person, and is told to them as decision 0049 tells a password changed or a first credential (`PasswordChanged`, `CredentialEnrolled`). Those costs come at the rate the load budget of the directory allows (section 3). A directory never removes a password: `"password": null`, an empty string and a `remove` of `password` answer `400 mutability`, a credential being revoked by an administrator (decision 0038). The password is `returned: never` (RFC 7643 §4.1.1, §7), whatever `attributes` names; it is never kept in the record (P-9), written to a log or an event, nor echoed in an error; and it is never a filter attribute (RFC 7643 §7 leaves the provider free not to allow it), a filter naming it answering `400 invalidFilter` (decision 0067). Each of these rules applies to the attribute a name resolves to (P-21), `urn:ietf:params:scim:schemas:core:2.0:User:password` among them. A password leaked, removed, or guessed outside the limit of decision 0014.
- **P-9. What the identity model cannot hold is kept as written, sealed, plain, bounded, and read by no client.** Every attribute of `User` and of `EnterpriseUser` a directory writes, but `password` and those section 6.3 keeps out of it, is kept in the record of that directory for the person, as it wrote it, sealed in the `user` family (decision 0011). Each of its strings is plain text as the core holds a value (`PlainText::holds()`, and `PlainText::holdsLines()` for `addresses.formatted` and `addresses.streetAddress`): no control, format or separator character but the joiners the scripts that write with them need, so that nothing a directory writes drives the terminal or the page that shows it; a URL it keeps (`photos.value` not selected, `manager.$ref`) is shown as text, never as a link. The record, as it is written, is held to the bound of section 7 after each write. SCIM reads it back as it was written, the archive of the person carries it as a chapter of its own, and the console and the administration API show it; no claim, no ID token, no UserInfo answer and no SAML assertion carries any of it but the values the claims take by section 6.6. The record handed to a relying party; a terminal driven by a value.
- **P-10. A claim takes one value, by a rule, and a verification is earned.** Each claim of the identity model takes the value section 6.6 names: the `primary` value of its attribute, else the first value of the type fixed there for it, else none. The `email` claim is verified only when the domain of its address, as `EmailDomain` writes it (its A-label, in lower case), is one the deployment declares for the directory, whole: a domain answers for its own addresses and for none under it, as a domain of an upstream identity provider does (`beffroi/saml` S-44); otherwise it is kept unverified for the person to confirm (`EmailConfirmation`). The `phone_number` claim is never verified until the person confirms it (decision 0063). A verification the person earned stays while the directory writes the same value, byte for byte, and goes with any other. No confirmation is sent because a directory wrote an address or a number: a confirmation is sent at the request of the person (decision 0014). A change of the address or of the number a directory writes is told to the person as any change of a channel is, by every channel decision 0049 reaches her by, the previous one included, the notice naming the channel that changed and never its old or new value, a channel never verified receiving nothing (beffroi-auth/beffroi#1451). A verification a directory grants itself; messages sent to whom a directory chose.
- **P-11. A person a directory learns of is an act; a group returns no person.** Each person a `GET` returns, by `id` or in a page, is an act `scim.answered` of that person, naming the directory as author (decisions 0022, 0066), written once the answer is made. So is each person a filter matches when the filter compares anything but `id`, `externalId` or `userName` by `eq` or `pr`, whether the page returns the person or not, `count=0` and a page past the end included: a filter and its `totalResults` would otherwise read a sealed attribute by bisection and leave no trace. So is the person a `PATCH` decided a value path on and found nothing, a `replace` answering `noTarget` or a `remove` that changes nothing: the silence of either tells the directory what the person's values are not. A write is the act of the write, and its answer is not a second one; a `304` returns nobody. A group names its members by their `id`, `$ref` and `type`, never their `display` (section 6.5): reading a group returns no person and writes no act. A read that leaves no trace.
- **P-12. The filter language is served whole, within bounds, and never against the sealed columns.** Every form of RFC 7644 §3.4.2.2 is served (section 6.8), the equalities on an attribute of enough entropy through an index; a comparison no index serves is evaluated in memory on the candidates of the directory, which are counted before one is opened and then opened, compared and dropped one at a time; past the bound of section 7 the query answers `400 tooMany` (RFC 7644 §3.4.2.1, §3.12). Nothing of a filter is written in clear, searched or sorted in the database but the columns the provider keeps in clear (decision 0011). An exhaustion of the process; personal data searched in clear.
- **P-13. A write answers what it wrote.** A creation answers `201` with the resource, its `Location` and its `ETag` (RFC 7644 §3.3), so its write is synchronous, the exception architecture §5.6 names; it goes through the one use case its operation calls, and what follows it, the journal, the notices, the logout tokens, leaves through the event bus of the core as everywhere. A write whose answer lies.
- **P-14. A write is conditional when the directory asks, serialised always, and a race is a conflict.** Every resource carries a weak `ETag`, `W/"n"`, `n` being the version the core counts for the person or the group, and the same value in `meta.version` (RFC 7643 §3.1, RFC 7644 §3.14). The version is raised once by each change; a change of membership raises the version of the group and of the person, the representation of both changing (`members`, `groups`). No write holds a lock on a person and on a group at once: a write locks the resource it writes, and the version of the other side, a group whose members a person's deletion changes or a person a group's members change, is raised once that write is committed, by one increment in a statement of its own that takes no other lock. Two writes can then never wait on each other, a group `PATCH` and a person `DELETE` included; the other side's `ETag` names the change a moment after its write. The comparison of `If-Match` and the raise of the version are one statement: a write that finds another version answers `412` and changes nothing. Every write to one resource holds a lock on it for its length, so that two writes without `If-Match` apply one after the other, each on what the other wrote, and no `add` is lost to the reading and writing of the record. Two creations of one username or of one group name that race end with one resource and one `409 uniqueness`, a unique constraint of the core deciding. An address, which no unique constraint holds, is checked and written under a lock on its blind index, whoever writes it, so that two creations, or a creation and a local registration, never both take it. A membership written twice at once is one row under a unique constraint on the group, the person and the source, the second write being the no-op RFC 7644 §3.5.2.1 asks of a value already there. Never `500`, nor two resources. A lost update; a duplicate.
- **P-15. A deletion is soft, and a deleted resource is gone for the protocol.** `DELETE` answers `204` (RFC 7644 §3.6); the person is deleted softly by the core (decision 0064), and from then on every operation on that `id` answers `404`, no query returns it, and its username and address no longer count for a conflict. The person leaves the groups of the directory at once, the version of each of them raised once the deletion is committed, as P-14 orders it; their other memberships wait for the purge (decision 0064). A person an administrator restores is local: the deleted `id` answers `404` for good. A deleted resource replayed.
- **P-16. A deactivation ends what the person holds, and the directory wins.** `active: false` disables the person through `PersonDisabling`, which ends every session of the core with what the end of a session triggers, the logout tokens and the revocation of the refresh tokens and of the opaque access tokens; `active: true` enables them through `PersonEnabling`. Both name the directory as author. The directory wins over a manual edit (decision 0002): `active` is no field the directory holds against a local edit, so an administrator can always disable a person of a directory, in an emergency or when its token has expired or its directory is no longer declared, and that disabling lasts until the directory writes `active: true` again, which enables the person. After a deactivation, an authorization request and a refresh for the person are refused, and the introspection of their tokens answers `active: false` (RFC 7662 §2.2). A person who left and still signs in.
- **P-17. A member is a person of the same directory, named by its `value`.** The `value` of a member names a `User` the same directory created; any other `id`, a group among them, answers `400 invalidValue`: a group that is a member of a group is not served. A member without a `value`, or named by its `$ref` alone, answers `400 invalidValue`. A membership written into another source; a cycle of groups.
- **P-18. A group of a directory administers nothing by its name.** A name of `BEFFROI_TENANT_ADMINISTRATORS` designates a local group; a group a directory holds administers the tenant only when the deployment names it with its directory (decision 0038). The administration taken by creating a group.
- **P-19. An error says the rule, never the value.** Every error carries the body of RFC 7644 §3.12, `schemas`, `status` as a JSON string, `scimType` where Table 9 has one, and a `detail` the module writes from the rule refused: never from the message of an exception, which may carry a value (`EmailAddress` names the address it refuses), and never from a value the request carried. Every refusal of the core a write can meet answers its SCIM error; anything else answers `500` with the error document and a `detail` that says only that the provider failed. A value echoed into a log or a proxy, a password among them.
- **P-20. Nothing of a request is logged but its path and the names of its parameters.** No body, no value of a parameter, no token. The access log of the image already keeps the names of the parameters and never their values (`apps/beffroi/frankenphp/Caddyfile`); the module adds no log of its own that would. A filter carries personal data in the query string (RFC 7644 §7.5.2). Personal data in a log.
- **P-21. A name resolves to one attribute, once.** A name in a body is an `ATTRNAME` of RFC 7643 §2.1 or `$ref`, the reference sub-attribute RFC 7643 §2.3.7 and §2.4 define, which an `ATTRNAME` cannot be since it begins with a letter; in US-ASCII, read without case by the folding of ASCII alone (RFC 7643 §2.1: « all ABNF strings are case insensitive and the character set for these strings is US-ASCII »). Any other name answers `400 invalidSyntax`, so that no folding of Unicode brings `paſſword` or a KELVIN SIGN onto a name. A name in a filter or in a `path` follows the grammar of RFC 7644 §3.4.2.2, whose `ATTRNAME` holds no `$`. A URN prefix is resolved against the URNs of the three schemas, case insensitive, the longest first, so that `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` is the container of its extension and never an attribute `User` of a shorter URN. The attribute notation of RFC 7644 §3.10 (`name.givenName`, `urn:…:enterprise:2.0:User:employeeNumber`) resolves to the attribute it names, in a path and in the keys of a value alike. Two names of one object that resolve to one attribute, or to an attribute and one of its sub-attributes (`userName` beside its URN form, `name` beside `name.givenName`), answer `400 invalidSyntax`, as a name written twice does (P-5). Every rule of this document applies to the attribute a name resolves to, never to the string written. An attribute read in two ways, or a check its spelling escapes.
- **P-22. What the provider announces is what is wired.** `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas` are derived from the classes that serve each capability and map each attribute, never from a list kept beside them (section 6.13). An announcement that lies.
- **P-23. The package stands on the core alone.** No class of `Beffroi\Scim` uses a class of `Beffroi\Oidc` or of `Beffroi\Saml`, and no class of the core uses a class of `Beffroi\Scim`; Deptrac refuses either (section 2). A protocol that reaches into another.

## 5. Public API

### 5.1 The endpoints served

The base path of a tenant ends in the version segment `v2`, right before the resource endpoint (RFC 7644 §3.13), on the protocol plane of the application. Every answer is `application/scim+json` (RFC 7644 §8.1), the format §3.8 defaults to, carries `Cache-Control: no-store`, and is written by the package.

| Endpoint | Method | Section | Answer |
|---|---|---|---|
| `/Users` | `GET` | RFC 7644 §3.4.2 | `200`, a `ListResponse` of the persons of the directory |
| `/Users` | `POST` | RFC 7644 §3.3 | `201`, the person created |
| `/Users/{id}` | `GET` | RFC 7644 §3.4.1 | `200`, the person, or `304` (section 6.11) |
| `/Users/{id}` | `PUT` | RFC 7644 §3.5.1 | `200`, the person replaced |
| `/Users/{id}` | `PATCH` | RFC 7644 §3.5.2 | `200`, the person patched |
| `/Users/{id}` | `DELETE` | RFC 7644 §3.6 | `204` |
| `/Groups` | `GET` | RFC 7644 §3.4.2 | `200`, a `ListResponse` of the groups of the directory |
| `/Groups` | `POST` | RFC 7644 §3.3 | `201`, the group created |
| `/Groups/{id}` | `GET` | RFC 7644 §3.4.1 | `200`, the group, or `304` |
| `/Groups/{id}` | `PUT` | RFC 7644 §3.5.1 | `200`, the group replaced |
| `/Groups/{id}` | `PATCH` | RFC 7644 §3.5.2 | `204`, or `200` with the group when the request names `attributes` |
| `/Groups/{id}` | `DELETE` | RFC 7644 §3.6 | `204` |
| `/ServiceProviderConfig` | `GET` | RFC 7644 §4, RFC 7643 §5 | `200`, the configuration, without a token |
| `/ResourceTypes`, `/ResourceTypes/{name}` | `GET` | RFC 7644 §4, RFC 7643 §6 | `200`, `User` and `Group` |
| `/Schemas`, `/Schemas/{urn}` | `GET` | RFC 7644 §4, RFC 7643 §7 | `200`, the three schemas |
| `/Bulk`, `/.search`, `/Users/.search`, `/Groups/.search`, `/Me` | any | RFC 7644 §3.7, §3.4.3, §3.11 | `501`, not served (section 8) |

### 5.2 What the application hands it

One use case per operation, which the application calls with the directory the token named (P-1) and what the request carries: the identifier of the path, the parameters of the query as pairs in their order, the `If-Match`, `If-None-Match` and `Prefer` headers, and the body as bytes. It gives back the status, the headers of RFC 7644 (`Location`, `Content-Location`, `ETag`) and the JSON document. The names of the classes are the stories' (section 12).

## 6. Processing rules

### 6.1 A request, in order

0. **The budget of the origin** (decision 0014), on every route of the module once it is named, before the token is read or anything is hashed, `/ServiceProviderConfig` included; past it, `429` (RFC 6585 §4).
1. **The token** (P-1), before anything else is read: no body is decoded for a request that names no directory, and no budget of a directory is spent.
2. **The load budget of the directory** (decision 0014), by tenant and by directory once the token is verified, never by token, so that a directory holding several tokens spends one budget, and never by a value the request chose; past it, `429`. Its numbers are the deployment's; their defaults are measured, with a margin, on what `castor scim` and the captured first synchronisation of Entra and Okta send (beffroi-auth/beffroi#1416, #1431, #1432), as decision 0014 measures every load budget.
3. **The identifier of the path**: one the directory's resources do not hold answers `404` (P-2), before the body is read.
4. **The body**: its `Content-Type` is `application/scim+json` or `application/json` (RFC 7644 §3.8), its type and subtype read without case (RFC 9110 §8.3.1), `charset` the one parameter accepted, its name and its value read without case and its value `utf-8` (RFC 9110 §5.6.6, §8.3.2), so that `charset=UTF-8` is accepted; a body without a `Content-Type` is read as `application/scim+json`, the format §3.8 defaults to; another type answers `415` (RFC 9110 §15.5.16). Its bytes are counted (section 7, `413` past the bound, RFC 9110 §15.5.14), then read by the reader of P-5, then decoded as JSON (RFC 8259) in UTF-8; bytes that are not UTF-8 JSON, and a top level that is not an object, answer `400 invalidSyntax`.
5. **The names** (P-21): each one an `ATTRNAME` or `$ref` in US-ASCII, folded by ASCII, its URN prefix and its notation resolved; two names resolving to one attribute refused.
6. **The schemas** of a resource in a body name the base schema of its endpoint, may name the `EnterpriseUser` extension on `/Users`, name nothing else and nothing twice (RFC 7643 §3); a missing base schema, an unknown URN and a duplicate answer `400 invalidValue`. An extension container the `schemas` of the body does not name, and an attribute none of its schemas defines, answer `400 invalidValue`: a value the provider would drop could not be read back as written (decision 0063). Some names are known and ignored, never refused: `meta` and its sub-attributes in every body, a `PATCH` included, as a value or as a `path` (RFC 7643 §3.1: « This attribute SHALL be ignored when provided by clients »), `id` and the `groups` of a `User` in a `POST` or a `PUT` (RFC 7644 §3.3, §3.5.1: `readOnly`), `members.display`, `members.$ref` and `manager.displayName` (sections 6.4, 6.5); in a `PATCH`, a `readOnly` attribute written with its current value changes nothing (section 6.10).
7. **The operation** (section 6.10), then the answer and its acts (P-11).

### 6.2 The common attributes

RFC 7643 §3.1 defines them for every resource. The **resource table** of the module holds one row per resource a directory pushed (beffroi-auth/beffroi#1424): the directory, the kind, the identifier of the core object, the `id`, the `externalId` sealed under a blind index, and the soft deletion of the resource.

| Attribute | RFC 7643, characteristics | Rule |
|---|---|---|
| `id` | §3.1; string, `readOnly`, `returned: always`, case exact | The module's (P-3), in the resource table; ignored in a `POST` or a `PUT`; in a `PATCH`, its current value changes nothing and another answers `400 mutability` (section 6.10); an `id` of a path that is not one of the directory's resources answers `404` (P-2) |
| `externalId` | §3.1; string, `readWrite`, case exact, issued by the client and scoped to its domain | In the resource table, sealed under a blind index; `eq` goes through that index (section 6.8); the provider enforces no uniqueness (§3.1), and an `externalId` is read within the resources of its directory only |
| `meta` | §3.1; complex, `readOnly` | Ignored in every body, a `PATCH` included, never answered `mutability` (§3.1: SHALL be ignored when provided by clients); written by the provider |
| `meta.resourceType` | §3.1; string, `readOnly`, case exact | `User` or `Group`, the endpoint the resource was created at (RFC 7644 §3.3.1) |
| `meta.created` | §3.1; dateTime, `readOnly` | The creation of the person or the group in the core, in UTC |
| `meta.lastModified` | §3.1; dateTime, `readOnly` | The last change of the person or the group in the core (beffroi-auth/beffroi#1422), in UTC, `meta.created` until a first change (§3.1) |
| `meta.location` | §3.1; reference, `readOnly` | The URL of the resource under the base path of the tenant, the same value as the `Content-Location` header of the answer (§3.1) |
| `meta.version` | §3.1; string, `readOnly`, case exact | The weak `ETag` of the resource, `W/"n"` (P-14, section 6.11) |
| `schemas` | §3; string, multi-valued, required | Read by step 6 of section 6.1; answered with the base schema, and with the `EnterpriseUser` URN when the record holds an attribute of the extension |

### 6.3 The `User` schema

RFC 7643 §4.1, `urn:ietf:params:scim:schemas:core:2.0:User`, its characteristics those of §8.7.1 unless the row says otherwise. **The identity model** is the person of the core: `User::$username`, the `Profile` of OIDC Core §5.1, one `EmailAddress`, one phone number, one `Address` of OIDC Core §5.1.1, and the state of the person. **The record** is what the directory wrote of the person, kept as written (P-9, beffroi-auth/beffroi#1419): a read answers each attribute from it, except `id`, `externalId`, `meta`, `userName`, `active` and `groups`, which are the provider's state (RFC 7644 §3.1: an answer reflects the resource as the service provider holds it), and `password`, which nothing answers. Each value is held to the bound of its kind in section 7 and to the plain text of P-9, and refused past them with `400 invalidValue`.

| Attribute | RFC 7643, characteristics | Identity model | Record and rule |
|---|---|---|---|
| `userName` | §4.1.1; string, required, case insensitive, `uniqueness: server` | `User::$username`, as written; prepared, enforced and compared by the UsernameCaseMapped profile of PRECIS (RFC 8265 §3.3, RFC 7644 §5, decision 0065) | Not in the record. Missing: `400 invalidValue`. Refused by PRECIS: `400 invalidValue`. Held by another person: `409 uniqueness` (P-2). Never copied to `preferred_username` |
| `name` | §4.1.1; complex | The parts below | Kept as written |
| `name.formatted` | §4.1.1; string | Claim `name` (OIDC Core §5.1), by section 6.6 | Kept as written |
| `name.familyName` | §4.1.1; string | Claim `family_name` | Kept as written |
| `name.givenName` | §4.1.1; string | Claim `given_name` | Kept as written |
| `name.middleName` | §4.1.1; string | Claim `middle_name` | Kept as written |
| `name.honorificPrefix` | §4.1.1; string | None: OIDC Core §5.1 has no such claim | Kept as written |
| `name.honorificSuffix` | §4.1.1; string | None | Kept as written |
| `displayName` | §4.1.1; string | Claim `name` when `name.formatted` is absent, by section 6.6 | Kept as written |
| `nickName` | §4.1.1; string | Claim `nickname` | Kept as written |
| `profileUrl` | §4.1.1; reference to an external resource | Claim `profile`, an absolute `https` or `http` URL (`Profile`), any other refused with `400 invalidValue` | Kept as written |
| `title` | §4.1.1; string | None | Kept as written |
| `userType` | §4.1.1; string | None | Kept as written |
| `preferredLanguage` | §4.1.1; string, the value of an `Accept-Language` header | None: the locale of an interaction comes from `ui_locales`, then `Accept-Language` | Kept as written |
| `locale` | §4.1.1; string, a language tag | Claim `locale`, plain text as the core holds it | Kept as written |
| `timezone` | §4.1.1; string, a name of the IANA time zone database | Claim `zoneinfo`, plain text as the core holds it | Kept as written |
| `active` | §4.1.1; boolean | The state of the person: `false` through `PersonDisabling`, `true` through `PersonEnabling` (P-16); `true` when a creation omits it; a local disabling lasts until the directory writes `true` (P-16) | Not in the record; answered from the state of the person |
| `password` | §4.1.1; string, `writeOnly`, `returned: never` | The password credential, prepared by the OpaqueString profile of PRECIS (RFC 8265 §4.2), through `UserProvisioner::setPassword()` (P-8) | Never in the record, never answered, never removed by a directory, never a filter attribute (P-8) |
| `emails` | §4.1.2; complex, multi-valued | Claim `email` by section 6.6, verified by P-10; the address it takes is unique among the persons of the tenant (P-2) | Every value kept as written |
| `emails.value` | §2.4, §4.1.2; string, an address of RFC 5321 | The value section 6.6 selects is an `EmailAddress`, refused with `400 invalidValue` when it is not one | Kept as written; each value of the record has a blind index, which `eq` goes through (section 6.8) |
| `emails.display` | §2.4; string | None | Kept as written |
| `emails.type` | §2.4, §4.1.2; string, canonical `work`, `home`, `other` | The type of section 6.6 is `work` | Kept as written; another value accepted (§4.1.2) |
| `emails.primary` | §2.4; boolean, `true` at most once | Selects the value of section 6.6 | Kept as written; a second `true` refused with `400 invalidValue` (§2.4) |
| `phoneNumbers` | §4.1.2; complex, multi-valued | Claim `phone_number` by section 6.6, never verified (P-10) | Every value kept as written |
| `phoneNumbers.value` | §2.4, §4.1.2; string, RFC 3966 recommended | The value section 6.6 selects, plain text of the core's phone number | Kept as written |
| `phoneNumbers.display` | §2.4; string | None | Kept as written |
| `phoneNumbers.type` | §2.4, §4.1.2; string, canonical `work`, `home`, `mobile`, `fax`, `pager`, `other` | The type of section 6.6 is `mobile` | Kept as written; another value accepted (§4.1.2) |
| `phoneNumbers.primary` | §2.4; boolean, `true` at most once | Selects the value of section 6.6 | Kept as written; a second `true` refused |
| `ims` | §4.1.2; complex, multi-valued | None | Every value kept as written |
| `ims.value` | §2.4; string | None | Kept as written |
| `ims.display` | §2.4; string | None | Kept as written |
| `ims.type` | §2.4, §4.1.2; string, canonical `aim`, `gtalk`, `icq`, `xmpp`, `msn`, `skype`, `qq`, `yahoo`, `other` | None | Kept as written; another value accepted (§4.1.2) |
| `ims.primary` | §2.4; boolean, `true` at most once | None | Kept as written; a second `true` refused |
| `photos` | §4.1.2; complex, multi-valued | Claim `picture` by section 6.6 | Every value kept as written |
| `photos.value` | §2.4, §4.1.2; reference to an external resource | The value section 6.6 selects is an absolute `https` or `http` URL (`Profile`), any other refused with `400 invalidValue` | Kept as written, shown as text (P-9) |
| `photos.display` | §2.4; string | None | Kept as written |
| `photos.type` | §2.4, §4.1.2; string, canonical `photo`, `thumbnail` | The type of section 6.6 is `photo` | Kept as written |
| `photos.primary` | §2.4; boolean, `true` at most once | Selects the value of section 6.6 | Kept as written; a second `true` refused |
| `addresses` | §4.1.2; complex, multi-valued | Claim `address` (OIDC Core §5.1.1) by section 6.6 | Every value kept as written |
| `addresses.formatted` | §4.1.2; string, may hold lines | `Address::$formatted`, lines separated by line feeds | Kept as written |
| `addresses.streetAddress` | §4.1.2; string, may hold lines | `Address::$streetAddress` (`street_address`) | Kept as written |
| `addresses.locality` | §4.1.2; string | `Address::$locality` | Kept as written |
| `addresses.region` | §4.1.2; string | `Address::$region` | Kept as written |
| `addresses.postalCode` | §4.1.2; string | `Address::$postalCode` (`postal_code`) | Kept as written |
| `addresses.country` | §4.1.2; string, an ISO 3166-1 alpha-2 code | `Address::$country` | Kept as written; a value that is not two ASCII letters refused with `400 invalidValue` (§4.1.2: MUST be in alpha-2 code format) |
| `addresses.type` | §2.4, §4.1.2; string, canonical `work`, `home`, `other` | The type of section 6.6 is `work` | Kept as written |
| `addresses.primary` | §2.4; boolean, `true` at most once | Selects the value of section 6.6 | Kept as written; a second `true` refused |
| `groups` | §4.1.2; complex, multi-valued, `readOnly` | The groups of the same directory the person is a direct member of (section 6.5) | Not in the record; ignored in a `POST` or a `PUT` (RFC 7644 §3.3, §3.5.1); in a `PATCH`, its current value changes nothing and another answers `400 mutability` (§3.5.2) |
| `groups.value` | §4.1.2; string, `readOnly` | The `id` of the group (P-3) | Answered |
| `groups.$ref` | §4.1.2; reference to a `Group`, `readOnly` | The `meta.location` of the group | Answered |
| `groups.display` | §2.4; string, `readOnly` | The name of the group, which names no person | Answered |
| `groups.type` | §4.1.2; string, canonical `direct`, `indirect`, `readOnly` | `direct`, the only membership there is without nested groups (P-17) | Answered |
| `entitlements` | §4.1.2; complex, multi-valued | None: an entitlement grants nothing, no role of the provider nor of Symfony | Every value kept as written |
| `entitlements.value` | §2.4; string | None | Kept as written |
| `entitlements.display` | §2.4; string | None | Kept as written |
| `entitlements.type` | §2.4; string | None | Kept as written |
| `entitlements.primary` | §2.4; boolean, `true` at most once | None | Kept as written; a second `true` refused |
| `roles` | §4.1.2; complex, multi-valued | None: a role grants nothing, no role of the provider nor of Symfony | Every value kept as written |
| `roles.value` | §2.4; string | None | Kept as written |
| `roles.display` | §2.4; string | None | Kept as written |
| `roles.type` | §2.4; string | None | Kept as written |
| `roles.primary` | §2.4; boolean, `true` at most once | None | Kept as written; a second `true` refused |
| `x509Certificates` | §4.1.2; complex, multi-valued | None: a certificate a directory pushes authenticates nothing | Every value kept as written |
| `x509Certificates.value` | §2.3.6, §4.1.2; binary, one DER certificate in base64 | None | Kept as written; a value that is not base64 (RFC 4648 §4), with or without its trailing padding (§2.3.6: « trailing padding characters MAY be omitted »), refused with `400 invalidValue` (§2.3.6: MUST be base64 encoded) |
| `x509Certificates.display` | §2.4; string | None | Kept as written |
| `x509Certificates.type` | §2.4; string | None | Kept as written |
| `x509Certificates.primary` | §2.4; boolean, `true` at most once | None | Kept as written; a second `true` refused |

The claims that section 6.6 maps are held by the directory as a whole, `userName` with them, whether a request names them or not, since a `PUT` clears what it omits (section 6.10): a manual edit of one of them is refused with the name of the directory (`UserSource::assertLeaves()`, beffroi-auth/beffroi#1417). `active` is not held (P-16). The claims no attribute maps, `preferred_username`, `website`, `gender` and `birthdate`, are not held, and the person says them of themselves where the tenant opens them.

### 6.4 The `EnterpriseUser` extension

RFC 7643 §4.3, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`, the attributes in a container of that name (RFC 7643 §3.3) or named with that URN (P-21). None of them is a claim of OIDC Core §5.1.

| Attribute | RFC 7643, characteristics | Identity model | Record and rule |
|---|---|---|---|
| `employeeNumber` | §4.3; string | None | Kept as written |
| `costCenter` | §4.3; string | None | Kept as written |
| `organization` | §4.3; string | None | Kept as written |
| `division` | §4.3; string | None | Kept as written |
| `department` | §4.3; string | None | Kept as written |
| `manager` | §4.3; complex | None | Kept as the reference the directory sent |
| `manager.value` | §4.3; string, the `id` of another `User` | None | Kept as written; not checked against the resources of the directory (RFC 7643 §2.3.7 leaves referential integrity to the provider, which does not enforce it here) |
| `manager.$ref` | §4.3; reference to a `User` | None | Kept as written, shown as text (P-9) |
| `manager.displayName` | §4.3; string, `readOnly`, optional | None | Ignored in a body (RFC 7644 §3.3) and never answered: answering it would read another person |

### 6.5 The `Group` schema

RFC 7643 §4.2, `urn:ietf:params:scim:schemas:core:2.0:Group`. A group of a directory is a `Group` of the core whose source is `scim` (`GroupSource::Scim`), managed (`GroupSource::isManaged()`): neither it nor its members are edited locally (beffroi-auth/beffroi#1421). A group has no record: each of its attributes is the core's or the resource table's.

| Attribute | RFC 7643, characteristics | Identity model | Rule |
|---|---|---|---|
| `displayName` | §4.2; string, required; announced `uniqueness: server` (section 6.13) | `Group::$name`, brought to NFC, then held to the rules of the core for a name | Missing, or refused by the core: `400 invalidValue`. Compared in the form of section 6.7 for its uniqueness, for a filter and under its unique constraint alike, so that `Sales` and `sales` are one name: a name that compares equal to the name of another group of the tenant, of any source, answers `409 uniqueness` (P-2). A name of `BEFFROI_TENANT_ADMINISTRATORS` grants nothing by itself (P-18) |
| `members` | §4.2; complex, multi-valued | The memberships of the group, of source `scim` | Counted before they are read (P-5); the members an answer would carry are counted in the database before one is loaded, and past the bound of section 7 the read answers `400 tooMany` (RFC 7644 §3.12), `GET /Groups/{id}` included, which Table 9 does not list for `tooMany` (it names §3.4.2 and §3.4.3, not §3.4.1): the provider departs from it there rather than answer a group without the members it asks. The same read with `excludedAttributes=members` answers the group without them |
| `members.value` | §4.2; string, `immutable`, the `id` of a resource | The person the `id` names | A `User` the same directory created; any other `id`, a `Group` included, `400 invalidValue`; a member without it `400 invalidValue` (P-17) |
| `members.$ref` | §4.2; reference to a `User` or a `Group`, `immutable` | None | Ignored in a body, and a member it names alone refused (P-17); answered as the `meta.location` of the member |
| `members.type` | §4.2; string, canonical `User`, `Group`, `immutable` | None | `User`, or absent; `Group` refused with `400 invalidValue` (P-17); answered `User` |
| `members.display` | §2.4; string, `immutable`; not in the `Group` schema of §8.7.1 | None | Ignored in a body, never kept, never answered (P-11) |

### 6.6 The claims a person takes from what a directory wrote

Each claim takes the `primary` value of its attribute (RFC 7643 §2.4), else the first value whose `type` is the one below, else none: the claim is then unset, and every value stays in the record. A singular attribute is taken as it is.

| Claim (OIDC Core §5.1) | Attribute | Type when no value is `primary` | Verification |
|---|---|---|---|
| `name` | `name.formatted`, else `displayName` | | |
| `given_name` | `name.givenName` | | |
| `family_name` | `name.familyName` | | |
| `middle_name` | `name.middleName` | | |
| `nickname` | `nickName` | | |
| `profile` | `profileUrl` | | |
| `picture` | `photos.value` | `photo`, the full image and not its thumbnail | |
| `zoneinfo` | `timezone` | | |
| `locale` | `locale` | | |
| `email` | `emails.value` | `work`, an enterprise directory's address of the person | Verified only inside the domains of the directory (P-10) |
| `phone_number` | `phoneNumbers.value` | `mobile`, the number a message of decision 0049 can reach | Never verified until the person confirms it (P-10) |
| `address` | the sub-attributes of `addresses` | `work` | |
| `sub` | none: drawn by the core (P-4) | | |
| `updated_at` | none: the last change of the person in the core | | |

### 6.7 Values and their comparison

- A string compares as the `caseExact` characteristic of its attribute says (RFC 7643 §7, RFC 7644 §3.4.2.2): a case exact one by its octets, as written; a case insensitive one by the canonical caseless match of the Unicode Standard (§3.13, D145), `NFD(toCasefold(NFD(x)))` on both sides, with the full case folding of Unicode (`mb_convert_case()` with `MB_CASE_FOLD`; `IntlChar::foldCase()` folds code point by code point and keeps « ß »). `userName` compares by the form PRECIS enforces (decision 0065, the core's, beffroi-auth/beffroi#1423), and the local part of an address in NFC without case, its domain folded (decision 0065).
- A dateTime is an `xsd:dateTime` with a date and a time (RFC 7643 §2.3.5), compared in time; the provider writes each one in UTC with `Z`. A value of a filter that is not one, or that names no offset to UTC, whose order beside one that names it is not defined, answers `400 invalidFilter`.
- A boolean and a binary value have no order (RFC 7644 §3.4.2.2, Table 3), and `co`, `sw` and `ew` take strings only (section 6.8).
- `null` and an empty array make an attribute unassigned (RFC 7643 §2.5): in a write they clear it, in a filter `eq null` matches an unassigned attribute and `ne null` an assigned one.

### 6.8 The filter

**The language** is the whole of RFC 7644 §3.4.2.2: the attribute operators of Table 3 (`eq`, `ne`, `co`, `sw`, `ew`, `pr`, `gt`, `ge`, `lt`, `le`), the logical operators of Table 4 (`and`, `or`, `not`), the grouping of Table 5, parentheses and value paths (`emails[type eq "work" and value co "@example.com"]`), under the grammar of Figure 1 and in the order of operations it gives: grouping, then `not` before `and` before `or`, then the attribute operators.

- Attribute names are read by P-21, and the operators without case (§3.4.2.2), the logical operators with them, an ABNF string being case insensitive (RFC 5234 §2.3); the literals `true`, `false` and `null` are those of JSON, in lower case.
- An attribute path may carry the URN of its schema (§3.10). A complex multi-valued attribute named without a sub-attribute stands for its `value` (`emails co "example.com"`, Figure 2), `members eq "…"` and `groups eq "…"` for `members.value` and `groups.value`. A singular complex attribute named without a sub-attribute, `manager eq "…"`, answers `400 invalidFilter`: §3.4.2.2 says « For complex attributes, a fully qualified sub-attribute MUST be specified », and Figure 2 shows the shorter form on a multi-valued attribute only. A multi-valued attribute matches when one of its values does (§3.4.2.2).
- A value path holds sub-attributes of its parent, never another value path: a complex attribute has no complex sub-attribute (RFC 7643 §2.3.8). A value path followed by a sub-attribute, `emails[type eq "work"].value eq "…"`, is the form of a `PATCH` path (Figure 7), not of a filter (Figure 1), and answers `400 invalidFilter`; the filter that says it is `emails[type eq "work" and value eq "…"]`.
- `co`, `sw` and `ew` take a string attribute and a string; `gt`, `ge`, `lt` and `le` a string, a number or a dateTime, and a boolean or a binary attribute answers `400 invalidFilter` (Table 3); a value of another JSON type than the attribute answers `400 invalidFilter`.
- `schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"` (§3.4.2.2) compares the schemas the resource has (section 6.2), in memory.
- A `userName` that PRECIS refuses names nobody: the comparison matches no person, and a query of it alone answers `200` with `totalResults` at 0.

**What it refuses**, each with `400 invalidFilter` (§3.4.2.2, Table 9): an operator the language does not define (`regex`); a filter the grammar does not read; a name outside US-ASCII (P-21); an attribute the schema of the endpoint does not define, and one the provider does not keep (`members.display`, `manager.displayName`); `password`, under every name it resolves from (P-8).

**How it is answered.** A comparison is answered by the database when it is one of these, and evaluated in memory otherwise:

| Endpoint | Answered by an index | Answered on a column kept in clear |
|---|---|---|
| `/Users` | `id eq`, `externalId eq` (the blind index of the resource table), `userName eq` (the blind index of the core, on the form PRECIS enforces), `emails.value eq`, alone or in a value path (the blind index of each address of the record), `groups.value eq` (the memberships); `pr` on `id`, `externalId` and `userName` | `eq`, `ne`, `gt`, `ge`, `lt`, `le` and `pr` on `meta.created` and `meta.lastModified`; `eq`, `ne` and `pr` on `active` |
| `/Groups` | `id eq`, `externalId eq`, `displayName eq` (on the form section 6.7 compares), `members.value eq` (the memberships); `pr` on `id`, `externalId` and `displayName` | `eq`, `ne`, `gt`, `ge`, `lt`, `le` and `pr` on `meta.created` and `meta.lastModified` |

An index serves the attributes of enough entropy that a filter looks up by equality, as decision 0011 keeps them; `title`, `department` or `locale` have none, and their comparisons are evaluated in memory. An `and` is answered on the candidates of the side the database answers; an `or` and a `not` that hold a comparison evaluated in memory take every resource of the directory for candidates. The candidates are the resources of the requesting directory only, never a deleted one (P-15); they are counted before one is opened, and past the bound of section 7 the query answers `400 tooMany` (§3.4.2.1). The remaining comparisons are evaluated in memory on the candidates, opened by the KMS as every sealed column is, one at a time, each compared and dropped before the next; nothing of them is written in clear, searched or sorted in the database (P-12).

### 6.9 Pagination and the attributes of an answer

- **Pagination** is by index (RFC 7644 §3.4.2.4). `startIndex` is 1 by default and a value below 1 is read as 1; `count` is 100 by default and at most, a larger one read as 100, a negative one as 0. A value that is not an integer answers `400 invalidValue`. The answer is a `ListResponse` (§3.4.2) with `totalResults`, `itemsPerPage`, `startIndex` and `Resources`; `Resources` is an empty array when the page holds nobody, with `count=0` or past the end, since §3.4.2 makes it REQUIRED whenever `totalResults` is not zero. A query that matches nothing answers `200` with `totalResults` at 0 (§3.4.2). The resources come in the stable order of the resource table, their creation order: sorting is not served (section 8). A page of groups holds fewer groups than `count` when the members of the next one would take the answer past the bound of section 7, as §3.4.2.4 lets a provider return fewer results; a group whose members alone pass it answers `400 tooMany` to the page it would open, or is read with `excludedAttributes=members`.
- **`attributes` and `excludedAttributes`** (RFC 7644 §3.4.2.5, §3.9) are served on every operation that returns a resource, as comma-separated names in the notation of §3.10 read by P-21, a schema URN naming its whole extension. They are mutually exclusive (§3.9): both answer `400 invalidValue`, and so does a name the schema does not define. `id` is always returned (`returned: always`), `password` never (`returned: never`), whatever either names.
- A parameter the provider does not recognize is ignored (§3.4.2), the `cursor` of RFC 9865 among them.

### 6.10 The operations

- **Creation**, `POST` (RFC 7644 §3.3): the attributes that are `readOnly` are ignored, a required one missing answers `400 invalidValue`, a conflict `409 uniqueness` (P-2, P-14). The answer is `201`, the resource, `Location` and `Content-Location` at its `meta.location`, and its `ETag` (P-13).
- **Reading**, `GET` (RFC 7644 §3.4.1, §3.4.2): `200`, or `304` when `If-None-Match` names the current version (section 6.11). Each person returned is an act (P-11).
- **Replacement**, `PUT` (RFC 7644 §3.5.1): never a creation (§3.2), an unknown `id` answering `404`, and a required attribute missing answering `400 invalidValue` (§3.5.1: a client MUST specify it). A `readWrite` attribute the body omits is cleared, as §3.5.1 lets the provider assume; two are left as they are, `active`, whose absence asserts no state the person could take, and `password`, which is `writeOnly` and which no directory can read back to send again. A `readOnly` attribute is ignored; the members of a group are replaced as a whole. The answer is `200` with the resource.
- **Patch**, `PATCH` (RFC 7644 §3.5.2): the body names `urn:ietf:params:scim:api:messages:2.0:PatchOp` and carries `Operations`, one operation at least, each with exactly one `op` (P-5, P-7) and a `path` of Figure 7, optional for `add` and `replace`, required for `remove`, which without one answers `400 noTarget` (§3.5.2.2). The operations apply in order and the request is atomic: one failure restores the resource whole and answers its error (§3.5.2).
  - The keys of a `value` without `path` are names in the notation of §3.10, resolved by P-21: `{"name.givenName": "…", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber": "…"}` sets those two attributes, §3.10 giving every operation one scheme of names and §3.5.2 adding an extension to the `schemas` of the person when one of its attributes is named with its URN.
  - A `primary` set to `true` sets every other value of its attribute to `false` (§3.5.2).
  - An `add` of a value already there changes nothing, neither the version nor `meta.lastModified` (§3.5.2.1). A value is already there when a member has the same `value`; when a singular attribute holds the same value; when a value of another multi-valued attribute is equal to it in every sub-attribute, compared as section 6.7 says. A value with the same `type` and the same `value` as one held but another sub-attribute is one change, which writes those sub-attributes on the value held rather than adding a second one (RFC 7643 §2.4: a service provider SHOULD NOT return the same (type, value) combination more than once per attribute), and raises the version once.
  - A `replace` whose value path names a multi-valued attribute that holds no value is an `add`, as §3.5.2.3 says of a target « that does not exist »: the value added is made of the equalities its value filter joins by `and` and of the sub-attribute its path names (`emails[type eq "work"].value` with `"x@example.com"` adds `{"type": "work", "value": "x@example.com"}`), and a value filter that is no such conjunction answers `400 noTarget`. On an attribute that holds values, a value path that matches none answers `400 noTarget` (§3.5.2.3: « no record match was made »). A `remove` whose value path matches nothing changes nothing.
  - `meta` is ignored, whatever the operation and the path (section 6.1). Another `readOnly` attribute, or an `immutable` one that has a value, written with the value it holds changes nothing, writing it again modifying nothing (§3.5.2: a client « MUST NOT modify » it); another value answers `400 mutability` (§3.5.2), and so does the removal of a required attribute (§3.5.2.2). A path the grammar does not read answers `400 invalidPath`.
  - A person patched answers `200` with the resource; a group `204`, or `200` with the group when the request names `attributes` (§3.5.2), since its answer would otherwise carry its members. A `PATCH` whose `attributes` asks for the members of a group counts them before anything is written, and past the bound of an answer answers `400 tooMany` and writes nothing.
- **Deletion**, `DELETE` (RFC 7644 §3.6): `204`, then P-15.
- **`Prefer: respond-async`** (RFC 9967 §2.5.1.1) is answered with the normal answer of the operation, which RFC 9967 allows; the asynchronous completion of a write is not served (section 8).

### 6.11 Versioning

`meta.version` and the `ETag` header carry the same weak entity tag, `W/"n"` (RFC 7643 §3.1, RFC 7644 §3.14), `n` the version of the person or the group in the core, raised by P-14. The tag is weak because the representation it validates varies with `attributes` and `excludedAttributes` (RFC 7643 §3.1: a version that is not a strong validator MUST be marked weak).

`If-Match` on `PUT`, `PATCH` and `DELETE`, and `If-None-Match` on `GET`, compare with the weak comparison of RFC 9110 §8.8.3.2. For `If-Match` this departs from RFC 9110 §13.1.1, which asks the strong comparison: RFC 7644 §3.14 names weak tags as the mechanism that keeps a client from overwriting another's changes and writes `If-Match: W/"..."` in its examples, which a strong comparison would never match. `If-Match: *` matches any resource the directory holds. An `If-Match` that matches nothing answers `412` (RFC 9110 §15.5.13, RFC 7644 §3.12) and writes nothing, the comparison and the write being one statement (P-14); an `If-None-Match` that matches answers `304` (RFC 9110 §15.4.5) with no body and with the `ETag`, `Content-Location` and `Cache-Control` a `200` would carry, as §15.4.5 requires of a `304`. A request without either is not conditional (§3.14: a client MAY supply `If-Match`).

### 6.12 Errors

Every error is the document of RFC 7644 §3.12 (P-19): `schemas` `["urn:ietf:params:scim:api:messages:2.0:Error"]`, `status` as a JSON string, `scimType` where the table has one, and a `detail` the module writes from the rule refused.

| Status | `scimType` | When |
|---|---|---|
| `400` | `invalidSyntax` | A body that is not a JSON object in UTF-8; a `PATCH` without its schema or its `Operations`; an `op` that is not one of the three (P-7); a `remove` with a `value` (P-7); a name that is neither an `ATTRNAME` nor `$ref`, a name written twice, two names resolving to one attribute (P-5, P-21) |
| `400` | `invalidValue` | A value of the wrong JSON type (P-6); a required attribute missing; `schemas` refused (section 6.1); an attribute no schema defines; a value refused by its bound, by plain text or by the core, a username PRECIS refuses, a password the core refuses (P-8); a second `primary`; a member of another source, a group, or a member without `value` (P-17); a `startIndex` or a `count` that is not an integer; `attributes` with `excludedAttributes`, or a name the schema does not define |
| `400` | `invalidFilter` | Section 6.8 |
| `400` | `tooMany` | The candidates of a filter, or the members an answer would carry, past their bound (sections 6.5, 6.9, 7) |
| `400` | `invalidPath`, `noTarget`, `mutability` | Section 6.10; `mutability` also for a password a directory would remove (P-8) |
| `401` | | P-1, with `WWW-Authenticate: Bearer realm="scim"`, and `error="invalid_token"` when a bearer token was presented |
| `403` | | A `filter` on `/ResourceTypes` or `/Schemas` (RFC 7644 §4) |
| `404` | | An `id` the directory does not hold (P-2), a deleted resource (P-15) |
| `409` | `uniqueness` | P-2, P-14 |
| `412` | | Section 6.11 |
| `413` | | A body past its bound (section 7) |
| `415` | | A `Content-Type` that is not one of the two (section 6.1, RFC 9110 §15.5.16) |
| `429` | | The budget of the origin, or the load budget of the directory (decision 0014) |
| `500` | | Anything no rule of this document names, with a `detail` that says only that the provider failed (P-19) |
| `501` | | What section 8 does not serve |

`sensitive` (RFC 7644 §7.5.2) is never answered: the connectors send their filters in the query string, `/.search` is not served, and the value of a parameter is in no log of the provider (P-20). What a proxy in front of a deployment or a tunnel to it logs of a query string is that deployment's to set, and its documentation says so (beffroi-auth/beffroi#1434).

### 6.13 Discovery

`/ServiceProviderConfig` (RFC 7643 §5), `/ResourceTypes` (§6) and `/Schemas` (§7) answer `GET` only (RFC 7644 §4). On `/ResourceTypes` and `/Schemas` the parameters of a query are ignored and a `filter` answers `403` (§4). Each capability is announced by the class that serves it, and each attribute of `/Schemas` read from the class that maps it (P-22, beffroi-auth/beffroi#1430):

| Capability | Announced |
|---|---|
| `patch` | `supported: true` (RFC 7644 §3.5.2) |
| `bulk` | `supported: false`, `maxOperations: 0`, `maxPayloadSize: 0` (§3.7, section 8) |
| `filter` | `supported: true`, `maxResults: 100`, the largest `count` (section 6.9) |
| `changePassword` | `supported: true` (P-8) |
| `sort` | `supported: false` (section 8) |
| `etag` | `supported: true` (section 6.11) |
| `authenticationSchemes` | One: `type: oauthbearertoken`, `name: OAuth Bearer Token`, a `description` of the token of a directory, its `specUri` RFC 6750 (RFC 7643 §5: `type`, `name` and `description` are REQUIRED; P-1) |
| `securityEvents` | Absent: RFC 9967 §4 reads its absence as no support (section 8) |

`/ResourceTypes` names `User`, endpoint `/Users`, schema `urn:ietf:params:scim:schemas:core:2.0:User`, with the extension `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`, `required: false`; and `Group`, endpoint `/Groups`. `/Schemas` describes the three schemas with the characteristics the provider applies, those of RFC 7643 §8.7.1 with these corrections: `displayName` of `Group` is `required: true` (§4.2) and `uniqueness: server` (section 6.5); `emails.value` keeps `uniqueness: none`, every value not being unique, and its `description` says that the address the person's claim takes is unique among the persons of the tenant (P-2); the sub-attributes the provider does not keep, `members.display` and `manager.displayName`, are not described.

`/ServiceProviderConfig` answers without a token, as RFC 7643 §5 asks of the authentication schemes (« the service provider SHOULD, with the appropriate security considerations, make the authenticationSchemes attribute publicly accessible without prior authentication »): its document holds what is wired and nothing of a tenant, its directories or its persons, and the request spends the budget of its origin as any other (decision 0014). `/ResourceTypes` and `/Schemas` ask the token of a directory as every other route (P-1).

## 7. Limits

| Bound | Value | Why |
|---|---|---|
| The body of a request | 524 288 bytes, counted before it is read; `413` past it | The provider's choice: a `PATCH` adding 1 000 members as RFC 7644 §3.5.2.1 writes one takes 148 116 bytes, 28 % of it; a body decoded whole by `json_decode()` builds about fifty-five times its size (a mebibyte of one-element arrays, 58 MiB on PHP 8.6.0), which the reader of P-5 keeps from happening; the bound is the module's, below the 2 MiB the image allows a body at its edge |
| The nesting of a body | 8 levels of arrays and objects; `json_decode()` is given a depth of 9 | The provider's choice: a `PATCH` of an address of a person nests 6, the deepest form these schemas take |
| The values of a body | 16 384 JSON values, arrays, objects, strings, numbers and literals together, counted by the reader of P-5 | The provider's choice: a `PATCH` of 1 000 members holds 4 008, a `User` at the bound of each of its lists 4 412; decoded, 16 384 values take about 2 MiB (one-element arrays, PHP 8.6.0) |
| The values of a multi-valued attribute of a `User`, the operations of a `PATCH`, the names of `attributes` or `excludedAttributes` | 100 each, counted before one is read; a `User` holds 100 values in an attribute after a write as before it | The bound of a list of a request (decision 0061; `docs/11-architecture/choix.md`, « Charge et déploiement ») |
| The members a request carries | 1 000, every operation of a `PATCH` together, counted before one is read | The provider's choice: a group lists the persons of a unit of the organisation, which a list of a request does not, and a `PUT` carries them all (RFC 7644 §3.5.1); a larger group is written by successive `PATCH` |
| The members an answer carries | 10 000, every group of a page together, counted in the database before one is loaded; past it, fewer groups in a page, or `400 tooMany` for one group alone | The provider's choice: 10 000 members answered as section 6.5 writes one (`value`, `$ref`, `type`, 137 bytes) take 1.4 MB; a larger group is read with `excludedAttributes=members`, its memberships found by `members.value eq` |
| The record of a person | 65 536 bytes, as the record writes it, after each write | The provider's choice: eighteen times the full enterprise user of RFC 7643 §8.3, 3 594 bytes written compactly, so that a page of 100 persons stays within a few MiB |
| The length of a filter, and of each `path` of a `PATCH` with its value filter | 4 096 bytes, decoded, counted before it is parsed | The provider's choice: percent-encoded, three times that still fits the 16 KiB the edge allows the request line and the headers, the token among them; a path is held to the bound of the filter it carries |
| The nesting of a filter or of a path | 10 levels of parentheses, value paths and `not` | The provider's choice: the filters of RFC 7644 §3.4.2.2, Figure 2, nest one level, and the reader holds a frame per level |
| The terms of a filter or of a path | 100 attribute expressions | The bound of a list of a request (decision 0061) |
| The candidates a filter evaluates in memory | 1 000 resources of the directory, opened one at a time; past them, `400 tooMany` | The provider's choice: ten pages of the largest `count`, compared within one request; a larger directory reaches its persons by an indexed equality (section 6.8) |
| `count` | 100 at most and by default | The largest page of the administration API (decision 0014), announced as `filter.maxResults` |
| A string | 255 characters; a reference 2 048; `addresses.formatted` and `addresses.streetAddress` 1 024, in lines; a phone number 64; plain text in each (P-9) | The bounds of the core's `PlainText`, which every value of the identity model already meets, applied to the record alike |
| A binary value | 8 192 characters of base64 | The provider's choice: a certificate of a person fits it many times, and the record bounds their sum |
| The lifetime of a token | A year by default and at most, set at issuance, never omitted; a longer one refused | Decision 0063, RFC 7644 §7.4; the default is the ceiling, so that no setting lengthens it (decision 0006) |
| The budget of an origin, the load budget of a directory | The numbers of the deployment; their defaults measured on `castor scim` and the captured first synchronisation (section 6.1) | Decision 0014 |

## 8. What is refused, what is not served

**Refused**, each with its rule:

- A boolean that is not the literal `true` or `false`, and every value of another JSON type than its attribute (P-6).
- An `op` other than `add`, `remove` and `replace` as RFC 7644 §3.5.2 writes them, and a `remove` that carries a `value` (P-7).
- A name outside US-ASCII, a name written twice, and two names resolving to one attribute (P-5, P-21).
- `password` as a filter attribute, `password` in any answer, and a password a directory would remove (P-8).
- A member that is a group, a person of another source, or a member without `value` (P-17): nested groups are not served.
- A schema other than `User`, `EnterpriseUser` and `Group`, and an attribute none of them defines (section 6.1): custom schemas are not served, for a tenant or for a directory.
- A singular complex attribute without its sub-attribute in a filter, and a value path followed by a sub-attribute in a filter (section 6.8).
- A token in a form body or in the query (RFC 6750 §2.2, §2.3), a Basic credential, an anonymous request, and a token of another tenant (P-1).

**Not served**, and announced so where RFC 7643 §5 has a place for it:

- `Bulk` (RFC 7644 §3.7): `bulk.supported: false`; `/Bulk` answers `501`.
- Sorting (RFC 7644 §3.4.2.3): `sort.supported: false`; a request that names `sortBy` or `sortOrder` answers `501` rather than a page in another order than the one asked.
- The search by `POST` (RFC 7644 §3.4.3): `/.search` answers `501`.
- `/Me` (RFC 7644 §3.11): `501`, as §3.11 asks of a provider that does not serve it.
- The pagination by cursor of RFC 9865: no `pagination` in `/ServiceProviderConfig`, and `cursor` ignored (section 6.9).
- The security events of RFC 9967 and the asynchronous completion of a write: no `securityEvents` in `/ServiceProviderConfig`, `Prefer: respond-async` answered normally (section 6.10). They are sub-spike 14d (beffroi-auth/beffroi#1413).
- The referential integrity of `manager` (section 6.4), the `display` of a member and the `displayName` of a manager (sections 6.4, 6.5).

## 9. Acceptance

Every test cites the rule it verifies, by its invariant or its section. The table says which story shows each rule; the story writes its rows here as it builds them.

| Rule | Story | What is shown |
|---|---|---|
| P-23, section 2 | beffroi-auth/beffroi#1414 | Deptrac refuses a class of `Beffroi\Scim` that uses a class of `Beffroi\Oidc` or of `Beffroi\Saml`, and a class of the core that uses a class of `Beffroi\Scim` |
| Section 5.1, P-5, P-19, P-20, P-21, section 6.1 steps 0, 4 and 5 | beffroi-auth/beffroi#1415 | SCIM off, every route answers `404`; on, the budget of the origin spent before the token; a body past the bound refused before it is decoded; a name twice, under an escape too, a nesting or a list past its bound refused before `json_decode()`; `$ref` read as a name and `paſſword` refused; a body that is not JSON `400 invalidSyntax`; a `Content-Type` absent read, `charset=UTF-8` accepted, another type `415`; every answer `application/scim+json` with `Cache-Control: no-store`; an unmapped failure a `500` whose `detail` carries nothing |
| P-1, section 6.13 | beffroi-auth/beffroi#1416 | A valid token reaches the routes; a revoked, an expired and an unknown token, a Basic credential and a token of another tenant answered `401` with `realm` and `error="invalid_token"`; `/ServiceProviderConfig` answered without a token; no issuance without an expiry, none past a year; the value in no table and no log; past the load budget of the directory, `429`, whatever token of the directory is presented |
| P-2, P-4, P-10, P-14 (the address) | beffroi-auth/beffroi#1417 | A person created by a directory names it as source; a held field edited locally refused; a held address refused, a race on one address ending with one person; an address of a declared domain verified, of a domain under it not; a phone number not verified; no confirmation sent by a write of the directory; a `sub` that is not the `externalId` |
| P-11, P-16 (the author) | beffroi-auth/beffroi#1418 | Each kind of author written and read back |
| P-9, sections 6.3, 6.6 | beffroi-auth/beffroi#1419 | Three typed phone numbers written and read back; the `phone_number` claim taking the primary one, else `mobile`; an escape sequence refused; a record past its bound refused; none of the record in clear in a dump; the archive carrying its chapter; no UserInfo answer carrying any of it |
| P-15 | beffroi-auth/beffroi#1420 | After a deletion, `404`, the address free for a new person, the person out of the groups of the directory; a restore local, the deleted `id` still `404` |
| P-17, P-18, section 6.5 | beffroi-auth/beffroi#1421 | A group created, renamed and deleted, a member added and removed, each with its event; a nested member refused; `Sales` refused beside `sales`; a bare name of `BEFFROI_TENANT_ADMINISTRATORS` granting nothing |
| P-14, section 6.11 | beffroi-auth/beffroi#1422 | Every change raising the version once, a membership raising the group's and the person's |
| Section 6.7 (`userName`) | beffroi-auth/beffroi#1423 | Usernames compared equal and not, refused and accepted, by PRECIS |
| P-8 (the preparation) | beffroi-auth/beffroi#1442 | A password prepared by the OpaqueString profile before it is hashed and compared |
| P-3, section 6.2 | beffroi-auth/beffroi#1424 | A directory listing its own rows only; `externalId eq` and `emails.value eq` through their index; no `externalId` nor address in clear in a dump; an `id` unchanged by every write |
| P-5, P-8, P-11, P-12, section 6.8 | beffroi-auth/beffroi#1425 | One filter per operator and per form of the grammar, evaluated; each refusal with its `scimType`; `password` refused under its URN form; the bound of the candidates answered `tooMany`; an act for each person a filter on a sealed attribute matches, with `count=0` |
| P-10 (the notice) | beffroi-auth/beffroi#1451 | A change of address written by a directory told to the previous address and to the other channels, the notice carrying neither value |
| P-11, section 6.9 | beffroi-auth/beffroi#1426 | A person read by `id` and in pages; another source's person not found; an empty query `200`; `Resources` empty with `count=0`; no `password` answered; one act per person returned |
| P-6, P-7, P-8, P-13, P-14, P-21, section 6.10 | beffroi-auth/beffroi#1427 | Creation, replacement and each form of patch, a `value` without `path` in the notation of §3.10 and a `replace` on an attribute without value among them; `409` on a held username and address and on a race; `412` on a stale `If-Match` and no write; two unconditional `PATCH` at once, neither lost; `"False"` and `Replace` refused; `meta` in a `PATCH` ignored; an `add` differing in one sub-attribute one change; a pushed password hashed, told to the person, never returned, never removed |
| P-15, P-16 | beffroi-auth/beffroi#1428 | A deactivation then the authorization request and the refresh refused and the introspection inactive; a local disabling undone by `active: true`; a reactivation; a deletion `204` then `404` |
| P-5, P-11, P-14, P-17, section 6.5 | beffroi-auth/beffroi#1429 | The group examples of RFC 7644 answered; a member of another source refused; members past their bound refused; a page of groups holding fewer groups past the bound of an answer; one membership added twice at once, one row; a group `PATCH` and the `DELETE` of one of its members at once, neither waiting on the other |
| P-22, section 6.13 | beffroi-auth/beffroi#1430 | A mapping class removed, its attribute leaving `/Schemas`; `uniqueness: server` on the name of a group; the three documents read by the discovery checks of scim2-tester |

## 10. Repository

In the shape of `beffroi/oidc` for the code, of `beffroi/saml` for the specification: developed in `src/scim` of the monorepo `beffroi-auth/beffroi` and mirrored read only into `beffroi-auth/scim` by the split, the tests and the toolchain staying in the monorepo.

```
src/scim/              the package, what the mirror carries
  composer.json        beffroi/scim, MIT, php >=8.4, ext-intl, ext-mbstring; beffroi/core at self.version (the release
                       line of the monorepo); PSR-4 Beffroi\Scim\ => src/; no dev dependency: the tools live in the phpqa
                       image
  README.md            the short version of this document
  spec/scim.md         this document, the law of the package
  src/                 Domain/, Exception/, Port/, Application/, Bridge/ (section 2), from the first class
tests/scim/            the suite of the package, the testsuite scim of .ci-tools/phpunit.xml.dist, from the first test
at the root            the toolchain of the monorepo:
  composer.json        beffroi/scim replaced at self.version, Beffroi\Scim\ and Beffroi\Scim\Tests\ autoloaded
  .ci-tools/           deptrac.yaml (the Scim* layers of section 2), phpstan.neon (the package analysed with the core
                       and beffroi/oidc, under their baseline), phpunit.xml.dist
  .github/workflows/   gitsplit.yml, which pushes the mirror
  .gitsplit.yml        src/scim to beffroi-auth/scim
```

The suite, the source directory of Infection and the paths of the analysis that name `src/scim/src` or `tests/scim` arrive with the first class and the first test: none of them may name a directory Git does not track.

**Versioning.** The release line of the monorepo: a version is a milestone of `beffroi-auth/beffroi`, tagged there and pushed to the mirror by the split.

## 11. Out of scope

Not built, not planned here, and not added without a change of this document:

- HttpFoundation's `Request` and `Response`, PSR-7, the routes, the console commands, the tables and the migrations (the application, decision 0007).
- A SCIM client, the provider pushing to another service; FastFed.
- `client_credentials` for a connector (beffroi-auth/beffroi#1436); the groups handed to a client (beffroi-auth/beffroi#1437); a local person handed over to a directory (beffroi-auth/beffroi#1438).
- The shared signals, SSF, CAEP and RISC (spike 14, beffroi-auth/beffroi#1409).

## 12. Left to the spike

Each item is marked **left**, with the issue it goes to, **open**, with who decides it, or **decided**, with the date and who decided it. None is built ahead.

**Left**: the stories of spike 10, in the order of their dependencies, each a pull request that builds the rules of this document it names in section 9 and writes there what it shows: beffroi-auth/beffroi#1415, the endpoints; #1416, the token, and the defaults of the load budget of a directory, measured on what #1431 and #1432 send; #1417, the directory as a source; #1418, the author of an act; #1419, the record; #1420, the soft deletion; #810, the event of an upstream membership; #1421, the groups and memberships; #1422, the version; #1423, PRECIS for a username; #1442, PRECIS for a password; #1424, the resource table; #1425, the filter; #1426, the reads; #1451, a change of a channel told to the previous one; #1427, the writes of a person; #767, the tokens of an ended session in the journal; #1428, the deactivation and the deletion; #1429, the groups; #1430, the discovery; #1431 and #1432, the judges; #1433, the page for a CISO; #1434, the public documentation, which tells the operator that a group of more than 10 000 members answers `tooMany` to a listing of groups that does not exclude their members, as Okta lists them (`GET /Groups?startIndex=1&count=100`), so that such a group is split or kept out of what the directory pushes (section 6.9).

**Decided** on 28 November 2026 by the maintainer: `/ServiceProviderConfig` answers without a token (section 6.13); a person an administrator disabled is enabled again when the directory writes `active: true` (P-16); a token lives a year at most (P-1); a password is prepared by the OpaqueString profile of PRECIS (P-8, beffroi-auth/beffroi#1442); a change of address or of phone number is told to every channel of the person, the previous one included, whoever made it, a directory over SCIM among its authors (P-10, decision 0049, beffroi-auth/beffroi#1451).
