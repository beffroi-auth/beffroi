# rp

A relying party of the development OP: a Symfony 8.2 application that signs a user in with the
`oidc_login` authenticator, as the client `rp` that `apps/op/config/packages/beffroi.yaml` declares, and
does nothing else, so that what is tried against the provider is tried from an application small enough
to be edited on the spot.

```bash
# at the root of the monorepo
castor start && castor provision
castor rp          # https://localhost:8003
castor rp --stop
```

`castor rp` writes `OIDC_CLIENT_SECRET` into `.env.local` from `OIDC_RP_SECRET` of `apps/op/.env.local`,
copies the root of the internal CA of Caddy into `var/caddy-root.crt`, where the scoped client `op.client`
of `config/packages/framework.yaml` reads it for every call to the provider (PHP on the host does not read
the keychain), and starts the Symfony CLI server again, which reads `.env.local` once, when it starts.

`/profile` requires a signed-in user and starts the login on its own, then shows what UserInfo answered
and the claims of the ID token; `/logout` ends the session here and at the provider (RP-Initiated
Logout), which sends the browser back to `/`. What the firewall asks for is `config/packages/security.yaml`:
change it, and the next request plays the change.
