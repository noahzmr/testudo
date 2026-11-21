#!/bin/sh
# Runs the flow-analysis baseline: the flow-table unit tests plus the
# namespace test that pushes known traffic through the real capture pipeline
# (internal/capture/baseline_linux_test.go).
#
# The namespace test needs CAP_NET_ADMIN over a private network namespace. It
# gets that, in order of preference:
#   1. natively  - as root, or through an unprivileged user namespace;
#   2. in Docker - when the host forbids unprivileged user namespaces (for
#                  example Ubuntu's AppArmor restriction), the statically
#                  linked test binary runs in a throwaway privileged container
#                  that has no network.
#
# Environment:
#   TESTUDO_NETNS_IMAGE          container image for step 2 (default: git config
#                                testudo.netnsImage, then alpine:3). Any image
#                                works; it is never pulled implicitly.
#   TESTUDO_BASELINE_ALLOW_SKIP  set to 1 to accept a skipped namespace test.
set -eu

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0")"
[ -f go.mod ] || cd ..

pkgs="./internal/flows ./internal/capture"

out=$(go test -count=1 -v $pkgs 2>&1) || {
	echo "$out" | grep -vE '^(=== |--- PASS|PASS$)' >&2
	echo "flow-baseline: FAILED" >&2
	exit 1
}
if ! echo "$out" | grep -q -- '--- SKIP: TestFlowBaseline'; then
	echo "flow-baseline: ok (native namespace)"
	exit 0
fi

image=${TESTUDO_NETNS_IMAGE:-$(git config --get testudo.netnsImage 2>/dev/null || echo alpine:3)}
if command -v docker >/dev/null 2>&1 && docker image inspect "$image" >/dev/null 2>&1; then
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	CGO_ENABLED=0 go test -c -o "$tmp/capture.test" ./internal/capture
	if docker run --rm --privileged --network none \
		-e TESTUDO_REQUIRE_NETNS=1 -v "$tmp:/t:ro" "$image" \
		/t/capture.test -test.run '^(TestFlowBaseline|TestCaptureFollowsNewInterfaces)$' -test.count=1 >"$tmp/log" 2>&1; then
		echo "flow-baseline: ok (container namespace, $image)"
		exit 0
	fi
	cat "$tmp/log" >&2
	echo "flow-baseline: FAILED" >&2
	exit 1
fi

if [ "${TESTUDO_BASELINE_ALLOW_SKIP:-}" = 1 ]; then
	echo "flow-baseline: unit tests ok, namespace test SKIPPED (allowed by TESTUDO_BASELINE_ALLOW_SKIP)" >&2
	exit 0
fi
cat >&2 <<EOF
flow-baseline: the namespace test could not run on this host.
  This host forbids unprivileged user namespaces and no usable container
  image was found ($image). Do one of:
    - docker pull $image                       (or set TESTUDO_NETNS_IMAGE /
      git config testudo.netnsImage to an image you already have)
    - sudo -E go test -count=1 ./internal/capture
    - TESTUDO_BASELINE_ALLOW_SKIP=1 to commit without it (not recommended)
EOF
exit 1
