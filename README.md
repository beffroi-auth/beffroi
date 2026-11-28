# beffroi/framework

An identity provider for the Symfony ecosystem: OAuth 2.0 and OpenID Connect, and SAML 2.0 both ways, as the identity provider of service providers and as the service provider of upstream identity providers.

| Package | Directory | What it is |
|---|---|---|
| `beffroi/core` | `src/core` | Identity core: tenants, users and where they come from, credentials, linked identities, groups, authentication sessions, keys. Pure PHP. |
| `beffroi/oidc` | `src/oidc` | OAuth 2.0 / OpenID Connect module: clients, authorization requests, grants, tokens, discovery, JWKS, UserInfo, logout. Pure PHP. |
| `beffroi/saml` | `src/saml` | SAML 2.0 module: the identity provider and the service provider of a tenant, their metadata, Single Logout on the session of the core. Pure PHP. |
| `beffroi/scim` | `src/scim` | SCIM 2.0 module: the persons and the groups the directories of a tenant push, mapped onto the identity model of the core. Pure PHP. |
| `beffroi/saml2-model` | `src/saml2-model` | The SAML 2.0 model: the `samlp:`, `saml:` and `md:` objects of Web Browser SSO and Single Logout, read strictly and validated in code. No HTTP. |
| `beffroi/saml2-bindings` | `src/saml2-bindings` | The HTTP-Redirect and HTTP-POST bindings of SAML 2.0, strings and arrays in and out. No HTTP object. |
| `beffroi/xml-security` | `src/xml-security` | XML security in three namespaces: `Core`, a safe DOM; `Dsig`, XML Signature; `Enc`, XML Encryption. |
| `beffroi/beffroi` | `apps/beffroi` | The application, FrankenPHP: the configuration of the provider, its controllers, its security, its persistence, the login and consent pages. |
| `beffroi/tui` | `apps/tui` | The terminal client of the administration of an instance: it talks to the administration API over HTTP and installs none of the packages above. |

Each directory is split into a read-only mirror, `beffroi-auth/<name>` (`application` for `apps/beffroi`). Issues and pull requests go here.

Requires PHP 8.4 or later and Symfony 8.2; the CI tests it on PHP 8.4, 8.5 and 8.6, and 8.5 is what runs locally. Licensed under MIT.

## Development

```bash
composer install
(cd apps/beffroi && composer install)
castor phpunit
castor prepare-pr
```

Every QA task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available. `castor start` and `castor provision` bring up the development stack on https://op.localhost; `castor conformance` plays the OpenID certification plans against it, `castor saml-sp` and `castor saml-idp` play the two SAML roles against SimpleSAMLphp.

The documentation is at [doc.beffroi.tech](https://doc.beffroi.tech) and the website at [beffroi.tech](https://beffroi.tech). The project has an account on [Bluesky](https://bsky.app/profile/beffroi.tech) and a page on [LinkedIn](https://www.linkedin.com/company/beffroi-auth).
