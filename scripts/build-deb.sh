#!/bin/sh
# Builds dist/testudo_<version>_<arch>.deb: the binary with PAM support,
# the systemd unit, the PAM service, /etc/default/testudo and the docs.
# The build runs offline in a Debian 12 image with Go and a C compiler,
# against the host's module cache.
#
# Environment:
#   TESTUDO_GO_IMAGE   build image (default: git config testudo.goImage,
#                      then golang:1.25-bookworm). Not pulled implicitly.
#   VERSION            package version (default: from git describe)
#   MAINTAINER         Maintainer field (default: Testudo maintainers)
set -eu

cd "$(git rev-parse --show-toplevel)"
image=${TESTUDO_GO_IMAGE:-$(git config --get testudo.goImage 2>/dev/null || echo golang:1.25-bookworm)}
if ! docker image inspect "$image" >/dev/null 2>&1; then
	echo "build-deb: image $image is not here; docker pull it or set TESTUDO_GO_IMAGE" >&2
	exit 1
fi
if [ -z "${VERSION:-}" ]; then
	VERSION=$(git describe --tags --match 'v[0-9]*' 2>/dev/null | sed 's/^v//; s/-/+/g') ||
		VERSION=0.0.0+git$(git log -1 --format=%cd --date=format:%Y%m%d).$(git rev-parse --short=12 HEAD)
	[ -n "$VERSION" ] || VERSION=0.0.0+git$(git rev-parse --short=12 HEAD)
fi
MAINTAINER=${MAINTAINER:-Testudo maintainers <maintainers@testudo.invalid>}
mkdir -p dist

docker run --rm --network none \
	-v "$PWD:/src:ro" -v "$PWD/dist:/dist" -v "$(go env GOMODCACHE):/go/pkg/mod:ro" \
	-e GOPROXY=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local -e CGO_ENABLED=1 \
	-e VERSION="$VERSION" -e MAINTAINER="$MAINTAINER" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
	-w /src "$image" sh -ec '
		export GOCACHE=/tmp/gocache
		arch=$(dpkg --print-architecture)
		root=/tmp/pkg
		install -d $root/DEBIAN $root/usr/bin $root/lib/systemd/system $root/etc/pam.d $root/etc/default $root/usr/share/doc/testudo
		go build -buildvcs=false -trimpath -tags pam -ldflags "-s -w" -o $root/usr/bin/testudo ./cmd/testudo
		install -m 0644 packaging/systemd/testudo.service packaging/systemd/testudo-dhcp@.service packaging/systemd/testudo-dhcpcd@.service packaging/systemd/testudo-pppoe@.service packaging/systemd/testudo-dhcpcd6@.service $root/lib/systemd/system/
		install -m 0644 packaging/pam.d/testudo $root/etc/pam.d/testudo
		install -m 0644 packaging/default/testudo $root/etc/default/testudo
		install -m 0644 LICENSE $root/usr/share/doc/testudo/copyright
		for d in README.md docs/operations.md; do [ -f "$d" ] && install -m 0644 "$d" $root/usr/share/doc/testudo/; done
		install -m 0644 packaging/debian/conffiles $root/DEBIAN/
		install -m 0755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm $root/DEBIAN/
		size=$(du -sk --exclude=DEBIAN $root | cut -f1)
		sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" -e "s|@MAINTAINER@|$MAINTAINER|" \
			packaging/debian/control.in > $root/DEBIAN/control
		out=/dist/testudo_${VERSION}_${arch}.deb
		dpkg-deb --root-owner-group -Zxz --build $root "$out" >/dev/null
		chown "$HOST_UID:$HOST_GID" "$out"
		echo "$out"
	' | sed "s|^/dist/|dist/|"
