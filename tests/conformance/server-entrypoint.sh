#!/bin/sh
# Entrypoint of the conformance suite server container: trusts the root of the certificate the OP
# serves (the one the op container publishes in the caddy_data volume, mounted read-only: the mkcert
# root of the machine or the internal CA of Caddy, docker/op/entrypoint.sh) and the self-signed
# certificate of the suite's own nginx, then starts the suite exactly as the upstream image does
# (gitlab.com/openid/conformance-suite, Dockerfile).
#
# Both go into the JVM truststore because the scripted browser of the suite (HtmlUnit, driven by the
# "browser" section of the plan configuration) runs inside this JVM: it signs in on https://op.localhost,
# then follows the redirect to https://localhost:8443/test/a/<alias>/callback, which the
# conformance-redirector sidecar of compose.yaml forwards from the loopback of this container to nginx.
set -eu

CA=/caddy/beffroi/root.crt
for i in $(seq 1 60); do
	[ -f "$CA" ] && break
	echo "Waiting for the CA of Caddy at $CA ($i/60)..."
	sleep 2
done
if [ -f "$CA" ]; then
	keytool -importcert -noprompt -trustcacerts -alias caddy-local -file "$CA" -cacerts -storepass changeit \
		&& echo "CA of Caddy trusted by the JVM" \
		|| echo "Could not import the Caddy CA; the OP must then be reachable with a publicly trusted certificate" >&2
else
	echo "No Caddy CA found; the OP must be reachable with a publicly trusted certificate" >&2
fi

NGINX=${NGINX_HOST:-conformance-nginx}:8443
NGINX_CERT=/tmp/conformance-nginx.crt
for i in $(seq 1 60); do
	keytool -printcert -sslserver "$NGINX" -rfc > "$NGINX_CERT" 2>/dev/null && break
	echo "Waiting for the certificate of the suite's nginx at $NGINX ($i/60)..."
	sleep 2
done
if [ -s "$NGINX_CERT" ]; then
	keytool -importcert -noprompt -trustcacerts -alias conformance-nginx -file "$NGINX_CERT" -cacerts -storepass changeit \
		&& echo "Certificate of the suite's nginx trusted by the JVM" \
		|| echo "Could not import the nginx certificate; the scripted browser will not reach the callback of the suite" >&2
else
	echo "No nginx certificate found; the scripted browser will not reach the callback of the suite" >&2
fi

exec java \
	-D"fintechlabs.base_url=${BASE_URL}" \
	-D"fintechlabs.base_mtls_url=${BASE_MTLS_URL}" \
	-D"spring.data.mongodb.uri=mongodb://${MONGODB_HOST}:27017/test_suite" \
	${SIGNING_KEY:+-D"fintechlabs.signingKey=${SIGNING_KEY}"} \
	${DEPRECATED_SIGNING_KEY:+-D"fintechlabs.deprecatedSigningKey=${DEPRECATED_SIGNING_KEY}"} \
	${PRIVATE_LINK_SIGNING_KEY:+-D"fintechlabs.privateLinkSigningKey=${PRIVATE_LINK_SIGNING_KEY}"} \
	-D"oidc.google.clientid=${OIDC_GOOGLE_CLIENTID}" \
	-D"oidc.google.secret=${OIDC_GOOGLE_SECRET}" \
	-D"oidc.gitlab.clientid=${OIDC_GITLAB_CLIENTID}" \
	-D"oidc.gitlab.secret=${OIDC_GITLAB_SECRET}" \
	${JAVA_EXTRA_ARGS:-} \
	-jar /server/fapi-test-suite.jar \
	-Djdk.tls.maxHandshakeMessageSize=65536
