#!/bin/sh
# Runs the OIDC end-to-end test against a real identity provider: a Keycloak
# container with the realm in realm.json. Everything in that realm (users,
# passwords, the client secret) exists for this test only.
#
# The container uses the host network because the provider calls the console
# back (back-channel logout). Ports: 18480 provider, 18182 console.
#
# Environment:
#   TESTUDO_KEYCLOAK_IMAGE   image to use (default: git config
#                            testudo.keycloakImage, then
#                            quay.io/keycloak/keycloak:26.8.1). Not pulled
#                            implicitly.
set -eu

cd "$(git rev-parse --show-toplevel)"
image=${TESTUDO_KEYCLOAK_IMAGE:-$(git config --get testudo.keycloakImage 2>/dev/null || echo quay.io/keycloak/keycloak:26.8.1)}
name=testudo-oidc-test
issuer=http://127.0.0.1:18480/realms/testudo

if ! docker image inspect "$image" >/dev/null 2>&1; then
	echo "oidc-test: image $image is not here; docker pull it or set TESTUDO_KEYCLOAK_IMAGE" >&2
	exit 1
fi
tmp=$(mktemp -d)
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network host \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-test-password \
	-v "$PWD/scripts/oidc-test/realm.json:/opt/keycloak/data/import/realm.json:ro" \
	"$image" start-dev --http-port=18480 --http-host=127.0.0.1 --import-realm >/dev/null

go build -o "$tmp/testudo" ./cmd/testudo
go test -c -o "$tmp/e2e.test" ./cmd/testudo

i=0
until TESTUDO_OIDC_WAIT=1 "$tmp/e2e.test" -test.run '^TestProviderIsUp$' >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -gt 90 ]; then
		docker logs "$name" 2>&1 | tail -20 >&2
		echo "oidc-test: the provider did not come up" >&2
		exit 1
	fi
	sleep 2
done

if TESTUDO_E2E_BIN="$tmp/testudo" TESTUDO_OIDC_ISSUER="$issuer" TESTUDO_OIDC_STOP="docker stop $name" \
	"$tmp/e2e.test" -test.run '^TestOIDCLoginEndToEnd$' -test.count=1 >"$tmp/log" 2>&1; then
	echo "oidc-test: ok ($image)"
else
	cat "$tmp/log" >&2
	echo "oidc-test: FAILED" >&2
	exit 1
fi
