# beffroi/scim

Part of [beffroi/framework](https://github.com/beffroi-auth/beffroi), developed in `src/scim` of that monorepo; this repository is
its read-only split. Issues and pull requests go to the monorepo.

The SCIM 2.0 module of the identity provider: the service provider of RFC 7643 and RFC 7644 for the directories a
deployment declares, which push the persons and the groups of a tenant to
[`beffroi/core`](https://github.com/beffroi-auth/core). Pure PHP, in the four layers of the identity provider's
packages; the HTTP request is the application's.

[`spec/scim.md`](spec/scim.md) is the law of the package: the code conforms to it, or the document changes first.
This file is its short version. A directory authenticates by a bearer token of its own, which expires, and sees and
writes only the persons and the groups it created. The `User` and `Group` schemas and the `EnterpriseUser` extension
are mapped, attribute by attribute, onto the identity model of the core, and what the model cannot hold is kept as
the directory wrote it, sealed, in a record of that directory that no client reads. The whole filter language of
RFC 7644 is served within bounds, equalities through an index; the pagination is by index, `count` a hundred at
most; every resource carries a weak `ETag` that `If-Match` is compared to. A boolean is a JSON literal, `op` one of
the three values of RFC 7644, `password` hashed and never returned nor filtered on. `Bulk`, sorting, the search by
`POST`, nested groups and custom schemas are not served. The package is being built by spike 10
([beffroi-auth/beffroi#84](https://github.com/beffroi-auth/beffroi/issues/84)): it holds its specification so far.

The package requires PHP 8.4 or later, the `intl` extension and `beffroi/core`.

## Development

From the root of the monorepo, which holds the toolchain of every package:

```bash
composer install
castor prepare-pr                                # Mago lint and format, Rector, PHPStan, Deptrac
castor deptrac                                   # the layers of section 2 and the graph of the packages
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available.

## Security

See the [security policy](https://github.com/beffroi-auth/beffroi/blob/0.2.x/SECURITY.md) of the monorepo: private reporting, an advisory and a CVE for
every fix.

## License

MIT, see the [LICENSE](https://github.com/beffroi-auth/beffroi/blob/0.2.x/LICENSE) of the monorepo.
