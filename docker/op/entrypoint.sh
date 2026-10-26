#!/bin/sh
# Entrypoint of the op container: what this container needs from the machine around it before the image
# sets the application up, then the image doing exactly what it does without this file.
#
# The certificate of the stack (issue #740). When "castor start" found an mkcert CA on the machine, mkcert
# issued there a certificate for every name the stack serves, and its directory is mounted on
# /stack-certificate: the site of SERVER_NAME loads it, and Caddy, which manages no name a loaded
# certificate covers, serves it for the mTLS host as well, whose client certificate policy and cipher
# suites are untouched. A browser that trusts mkcert then trusts a stack started from any folder.
# Otherwise /stack-certificate is the directory of compose.yaml with nothing in it, and Caddy issues from
# its internal CA, which is what a CI runner gets.
#
# Whichever authority signed what is served, its root is published at one path of caddy_data,
# /data/beffroi/root.crt: the copy of the mkcert root castor put beside the certificate (the key of that
# root never leaves the machine), or a link to the root of the internal CA. That is what "castor" copies
# out for the walks (caddy_ca()) and what the conformance suite imports (tests/conformance/server-entrypoint.sh).
#
# The certificate of the conformance suite, when the suite is up (issue #363): the registration endpoint
# reads the document behind a "sector_identifier_uri" (OIDC Registration §5), and the module of the Dynamic
# plan that judges it serves that document from the suite itself, at an address naming localhost:8443. The
# sidecar of compose.yaml brings that port into this namespace, and this is what makes its certificate
# verifiable. Nothing of it runs when the suite is not up.
#
# The chain is the other way round from the worker's: there the script runs behind docker-entrypoint and
# ends in the consumer, here it runs in front of it and ends in it, because everything docker-entrypoint
# does for this container (the install, the wait on the database, the migrations, the stylesheet) it only
# does when the command it is given starts with "frankenphp".
set -eu

STACK_ROOT=/data/beffroi/root.crt
mkdir -p "$(dirname "${STACK_ROOT}")"
rm -f "${STACK_ROOT}"
if [ -f /stack-certificate/cert.pem ] && [ -f /stack-certificate/key.pem ] && [ -f /stack-certificate/root.pem ]; then
	CADDY_SERVER_EXTRA_DIRECTIVES="${CADDY_SERVER_EXTRA_DIRECTIVES:-}
tls /stack-certificate/cert.pem /stack-certificate/key.pem"
	export CADDY_SERVER_EXTRA_DIRECTIVES
	cp /stack-certificate/root.pem "${STACK_ROOT}"
	echo "The stack serves the certificate mkcert issued on the machine"
else
	ln -s ../caddy/pki/authorities/local/root.crt "${STACK_ROOT}"
	echo "The stack serves certificates of the internal CA of Caddy"
fi

CONFORMANCE_TRUST_COSTS="the sector identifier documents the Dynamic plan serves will not be read"
export CONFORMANCE_TRUST_COSTS
. /entrypoint/trust-nginx.sh

exec docker-entrypoint "$@"
