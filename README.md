# beffroi/framework

An identity provider for the Symfony ecosystem: OAuth 2.0 and OpenID Connect, and SAML 2.0 both ways, as the identity provider of service providers and as the service provider of upstream identity providers.

| Package | Directory | What it is |
|---|---|---|
| `beffroi/core` | `src/core` | Identity core: tenants, users and where they come from, credentials, linked identities, groups, authentication sessions, keys. Pure PHP. |
| `beffroi/oidc` | `src/oidc` | OAuth 2.0 / OpenID Connect module: clients, authorization requests, grants, tokens, discovery, JWKS, UserInfo, logout. Pure PHP. |
| `beffroi/saml` | `src/saml` | SAML 2.0 module: the identity provider and the service provider of a tenant, their metadata, Single Logout on the session of the core. Pure PHP. |
| `beffroi/saml2-model` | `src/saml2-model` | The SAML 2.0 model: the `samlp:`, `saml:` and `md:` objects of Web Browser SSO and Single Logout, read strictly and validated in code. No HTTP. |
| `beffroi/saml2-bindings` | `src/saml2-bindings` | The HTTP-Redirect and HTTP-POST bindings of SAML 2.0, strings and arrays in and out. No HTTP object. |
| `beffroi/xml-security` | `src/xml-security` | XML security in three namespaces: `Core`, a safe DOM; `Dsig`, XML Signature; `Enc`, XML Encryption. |
| `beffroi/symfony-bundle` | `src/symfony` | Symfony integration: configuration, controllers, security, persistence, the login and consent pages. |
| `beffroi/op` | `apps/op` | The standalone application, FrankenPHP. |

Each directory is split into a read-only mirror, `beffroi-auth/<name>` (`symfony-bundle` for `src/symfony`). Issues and pull requests go here.

Requires PHP 8.4 and Symfony 8.2; PHP 8.5 is what runs, locally and in CI. Licensed under MIT.

## Development

```bash
composer install
(cd apps/op && composer install)
castor phpunit
castor prepare-pr
```

Every QA task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available. `castor start` and `castor provision` bring up the development stack on https://op.localhost; `castor conformance` plays the OpenID certification plans against it, `castor saml-sp` and `castor saml-idp` play the two SAML roles against SimpleSAMLphp.

The design, the decisions and the spikes live in [beffroi-auth/design](https://github.com/beffroi-auth/design).
