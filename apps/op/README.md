# beffroi/op

The standalone identity provider: a Symfony skeleton on `beffroi/symfony-bundle`, served by FrankenPHP,
with PostgreSQL and RabbitMQ behind it. It is the recommended deployment, the form the provider takes for
whoever runs one rather than installs it inside an application of their own.

It is the `apps/op` directory of the monorepo, [beffroi-auth/beffroi](https://github.com/beffroi-auth/beffroi),
beside the packages it installs: the identity core, the OAuth 2.0 and OpenID Connect module and the Symfony
bundle. `beffroi-auth/op` is a mirror of that directory, read only, pushed by git split. The design and the
decisions are in [beffroi-auth/design](https://github.com/beffroi-auth/design), and the reference relying
party in [beffroi-auth/oidc-demo](https://github.com/beffroi-auth/oidc-demo).

## What is here, and what is not

Here: what a deployment decides. The layout the pages of the bundle take and the stylesheet that gives
them their look (Tailwind and DaisyUI), the firewall, the Messenger contract and its transports, the
migrations, the FrankenPHP and Caddy configuration with the host that asks for a client certificate, the
authorization detail types this deployment wires, and the page of what the provider holds of a person,
which this application owns and serves in place of the bundle's. Its suite is here too, in `tests/`: it
boots this kernel, on the database and the KMS that kernel needs, and reads the page that belongs to it.

Not here: the protocol and the identity model, which are the packages; and the development stack, the
castor tasks, the conformance plans and the demonstration walks, which sit at the root of the monorepo and
drive this application from a working copy.

## Working on it

Everything that builds, provisions, judges or demonstrates runs from the root above:

```bash
git clone git@github.com:beffroi-auth/beffroi.git && cd beffroi
composer install && (cd apps/op && composer install)
castor start            # https://op.localhost, PostgreSQL, RabbitMQ
castor provision        # the tenant, its keys, the first user, the client certificate
castor app-phpunit      # the suite of this directory, against the PostgreSQL the stack publishes
```

`beffroi/*` is resolved by path repositories to `../../src/*`, so this directory installs nothing on its
own: the application is worked on inside the monorepo, and deployed from a build rather than from a clone.

## Issues and pull requests

They are the monorepo's, the application's as much as the packages'. A mirror is read only.

## Licence

Its `composer.json` declares MIT, as the packages do.
