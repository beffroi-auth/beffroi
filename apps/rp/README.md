# rp

A relying party of the development OP: a Symfony 8.2 application that signs a user in with the
`oidc_login` authenticator, as the client `rp` that `apps/op/config/packages/beffroi.yaml` declares, and
does nothing else, so that what is tried against the provider is tried from an application small enough
to be edited on the spot.

```bash
# at the root of the monorepo
castor start && castor provision
castor rp          # https://rp.localhost
castor rp --stop
```

`castor rp` writes `OIDC_CLIENT_SECRET` into `.env.local` from `OIDC_RP_SECRET` of `apps/op/.env.local`,
then starts the `rp` service of `compose.yaml` (profile `rp`), which installs the application the first
time. The Caddy of `op` serves `rp.localhost` under its internal CA, like `op.localhost`, and passes it to
that service (`docker/rp/rp.Caddyfile`). The service runs without worker mode: an edit is served by the
next request, and `.env.local` is read at each one.

`/profile` requires a signed-in user and starts the login on its own, then shows what UserInfo answered
and the claims of the ID token; `/logout` ends the session here and at the provider (RP-Initiated
Logout), which sends the browser back to `/`. What the firewall asks for is `config/packages/security.yaml`.

The calls to the provider go through `op.client` (`config/services.yaml`), verified against the root of
the internal CA of Caddy read from the volume of `op`, and made with PHP streams: curl answers every
`*.localhost` name with the loopback address itself and would never reach the alias `op.localhost` has on
the network of the stack.
