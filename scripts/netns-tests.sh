#!/bin/sh
# Runs every real-kernel integration test (network namespaces, nftables) and
# fails if one of them cannot run. As root they run natively; otherwise the
# statically linked test binaries run in a throwaway privileged container
# without network (see scripts/netns-image/Dockerfile).
#
#   TESTUDO_NETNS_IMAGE   image to use (default: git config testudo.netnsImage,
#                         then testudo-netns:12)
set -eu
cd "$(git rev-parse --show-toplevel)"

pkgs="./internal/capture ./internal/fwrender ./internal/fwbridge ./internal/fwstage ./internal/frrender ./internal/frrstage ./internal/lbstage ./cmd/testudo"
pattern='^(TestFlowBaseline|TestModelDrivesTheKernel|TestGoldenRulesetLoadsIntoAKernel|TestRulesetOnARealKernel|TestGoldenConfigPassesFRRCheck|TestRoutingOnARealKernel|TestPrivilegedPathEndToEnd|TestVPNEndToEnd|TestKernelBalancingOnARealKernel|TestProxyOnARealKernel|TestPublishedServiceNeedsLogin|TestClusterEndToEnd|TestFabricEndToEnd|TestProxyPrefersLocalBackends)$'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The end-to-end test drives the real binary with privilege separation.
CGO_ENABLED=0 go build -o "$tmp/testudo" ./cmd/testudo

if [ "$(id -u)" = 0 ]; then
	TESTUDO_REQUIRE_NETNS=1 TESTUDO_E2E_BIN="$tmp/testudo" go test -count=1 -run "$pattern" $pkgs
	exit
fi

image=${TESTUDO_NETNS_IMAGE:-$(git config --get testudo.netnsImage 2>/dev/null || echo testudo-netns:12)}
if ! docker image inspect "$image" >/dev/null 2>&1; then
	echo "netns-tests: image $image not found; build it with:" >&2
	echo "  docker build -t testudo-netns:12 scripts/netns-image" >&2
	exit 1
fi
for p in $pkgs; do
	CGO_ENABLED=0 go test -c -o "$tmp/$(basename "$p").test" "$p"
done
for bin in "$tmp"/*.test; do
	docker run --rm --privileged --network none -e TESTUDO_REQUIRE_NETNS=1 -e TESTUDO_E2E_BIN=/t/testudo -v "$tmp:/t:ro" "$image" \
		"/t/$(basename "$bin")" -test.run "$pattern" -test.count=1 >"$tmp/log" 2>&1 || {
		cat "$tmp/log" >&2
		echo "netns-tests: FAILED in $(basename "$bin")" >&2
		exit 1
	}
	echo "netns-tests: ok $(basename "$bin" .test)"
done
