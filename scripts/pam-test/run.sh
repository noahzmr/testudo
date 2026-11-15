#!/bin/sh
# Runs the PAM end-to-end test: the binary built with the "pam" tag, as root
# in a throwaway container, against real host accounts (pam_unix, shadow,
# pam_faillock). The container has no network; modules come from the host's
# module cache, read-only.
#
# Environment:
#   TESTUDO_GO_IMAGE   a Debian 12 image with Go and a C compiler (default:
#                      git config testudo.goImage, then golang:1.25-bookworm).
#                      Not pulled implicitly.
set -eu

cd "$(git rev-parse --show-toplevel)"
image=${TESTUDO_GO_IMAGE:-$(git config --get testudo.goImage 2>/dev/null || echo golang:1.25-bookworm)}
if ! docker image inspect "$image" >/dev/null 2>&1; then
	echo "pam-test: image $image is not here; docker pull it or set TESTUDO_GO_IMAGE" >&2
	exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if docker run --rm --network none \
	-v "$PWD:/src:ro" -v "$(go env GOMODCACHE):/go/pkg/mod:ro" \
	-e GOPROXY=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local -e CGO_ENABLED=1 \
	-e TESTUDO_PAM_E2E=1 -e TESTUDO_E2E_BIN=/tmp/testudo -e TESTUDO_PAM_STACK=/src/packaging/pam.d/testudo \
	-w /src "$image" sh -ec '
		export GOCACHE=/tmp/gocache
		go build -buildvcs=false -tags pam -o /tmp/testudo ./cmd/testudo
		go test -tags pam -count=1 ./internal/pamauth
		go test -tags pam -count=1 -run "^TestPAMLoginEndToEnd$" ./cmd/testudo
	' >"$tmp/log" 2>&1; then
	echo "pam-test: ok ($image)"
else
	cat "$tmp/log" >&2
	echo "pam-test: FAILED" >&2
	exit 1
fi
