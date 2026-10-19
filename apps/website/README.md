# Beffroi website

The website of Beffroi, served at https://beffroi.tech. For now:

- `/`, a teaser;
- `/symfonycon`, the landing page of SymfonyCon Warsaw 2026 and its sign-up form, with the scene of the gate drawn
  small;
- `/privacy`, the privacy notice of the sign-ups;
- `/admin`, the back office of the leads (EasyAdmin): the list, a status and notes per lead, the CSV export, and the
  deletion that honours a request for erasure.

Symfony 8.2, PHP 8.5, PostgreSQL, Twig and AssetMapper (no Node, no build step). The public pages set no cookie and
load nothing from another site; their only script is the scene of the gate.

It lives in `apps/website` of the monorepo, an application of its own beside `apps/op`: its own `composer.json`, its
own lock and its own `vendor`, and nothing of the identity provider required. No mirror carries it.

## How a sign-up works

The form posts to the page itself, without JavaScript. CSRF protection is stateless (the `Sec-Fetch-Site` and
`Origin` headers of the browser), so the page starts no session. A valid sign-up is stored, confirmed by email from
`bonjour@beffroi.tech` through Sweego, and redirected to the thank-you page.

One lead per email address: signing up again updates the lead and sends no second confirmation, and the answer is the
same whether the address was known or not. A confirmation that failed to send is logged and tried again at the next
sign-up of that address.

Sweego reports what became of each confirmation on `POST /webhook/sweego`, signed with the secret of the webhook:
delivered, opened, clicked, bounced, reported as spam, unsubscribed, each written on the lead with its date and shown
in the back office (`src/Lead/SweegoEvents.php`). Opens and clicks need the tracking of Sweego, on in its settings, and
the tracking domain `t.beffroi.tech`.

A lead is kept twelve months after its last consent: `app:leads:purge`, run every day by the Scalingo scheduler
(`cron.json`), deletes the older ones.

## Run it

From `apps/website`:

```bash
composer install
docker compose up -d --wait                               # PostgreSQL, and Mailpit for the emails
symfony console doctrine:migrations:migrate --no-interaction
symfony console app:admin:create you@example.com          # asks the password twice
symfony server:start -d                                   # then open /symfonycon
```

The Symfony CLI hands the addresses of the containers to the application (`DATABASE_URL`, `MAILER_DSN`): run the
console and the tests through it. The emails land in Mailpit (`docker compose port mailer 8025`).

## Check it

From the root of the monorepo, as the Website workflow does (`.github/workflows/website.yml`):

```bash
castor website-phpunit     # the suite, on the PostgreSQL of compose.yaml unless DATABASE_URL names one
castor website-phpstan     # PHPStan at level max, with its Symfony and Doctrine extensions
castor mago-format && castor mago-lint && castor rector   # the formatter, the linter and Rector of the monorepo
```

## Deploy it on Scalingo

The Scalingo app `beffroi-tech` is deployed from an archive of this directory, from the root of the monorepo:

```bash
git archive --prefix=website/ HEAD:apps/website | gzip > website.tar.gz
scalingo --app beffroi-tech deploy website.tar.gz
```

The PHP buildpack (Nginx and PHP-FPM) reads `composer.json`: PHP `~8.5`, the document root `public/`, the Nginx
include of the login, the compilation of the assets (`asset-map:compile`) and the log file it streams
(`var/log/prod.log`). `Procfile` plays the migrations after each deployment, `cron.json` schedules the purge.

While the site is not public, Nginx asks for a login on every URL but `/webhook/sweego`
(`config/nginx-basic-auth.conf`). The build writes `config/htpasswd` from `HTPASSWD_CONTENT`, and fails without it. The
file is written at build time only: a new login takes a new deployment. To open the site, remove the include from
`extra.paas.nginx-includes` and the two lines of `extra.paas.compile` that read `HTPASSWD_CONTENT`.

Environment variables:

| Name | Value |
|---|---|
| `APP_ENV` | `prod` |
| `APP_SECRET` | 32 random bytes, hex encoded |
| `DATABASE_URL` | `$SCALINGO_POSTGRESQL_URL`, if Scalingo does not set it already |
| `MAILER_DSN` | `sweego+api://<API key>@default` |
| `SWEEGO_WEBHOOK_SECRET` | the secret of the webhook, as the dashboard of Sweego gives it |
| `DEFAULT_URI` | `https://beffroi.tech`, for the URLs of the console |
| `HTPASSWD_CONTENT` | `htpasswd -n <user>`: the login of the private site, read at build time |

The application trusts the router of Scalingo for `X-Forwarded-For`, `-Proto` and `-Port` (`config/packages/framework.yaml`).
The sessions of the back office live in `var/`, so a deployment signs the admins out.

## The QR code

`brand/qr-symfonycon.svg` points to https://beffroi.tech/symfonycon, error correction Q, a quiet zone of four modules:
print it as it is, at 2 cm across at least.
