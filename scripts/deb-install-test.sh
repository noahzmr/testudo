#!/bin/sh
# Installs the newest dist/testudo_*.deb in a throwaway Debian 12 container
# (the netns test image, which has the package's dependencies) and checks
# the result: files and modes, the admin group, the service's command line
# serving /healthz and /readyz, then removal and purge.
set -eu

cd "$(git rev-parse --show-toplevel)"
deb=$(ls -t dist/testudo_*.deb 2>/dev/null | head -1)
[ -n "$deb" ] || { echo "deb-install-test: no package in dist/; run scripts/build-deb.sh" >&2; exit 1; }
image=testudo-netns:12

docker run --rm --privileged --network none -v "$PWD/dist:/dist:ro" -e DEB="/$deb" "$image" sh -ec '
	fail() { echo "deb-install-test: $*" >&2; exit 1; }
	dpkg -i "$DEB" >/tmp/dpkg.log 2>&1 || { cat /tmp/dpkg.log; fail "dpkg -i failed"; }
	test -x /usr/bin/testudo || fail "no binary"
	for f in /lib/systemd/system/testudo.service /lib/systemd/system/testudo-dhcp@.service /lib/systemd/system/testudo-dhcpcd@.service /etc/pam.d/testudo /etc/default/testudo /usr/share/doc/testudo/copyright; do
		test -f "$f" || fail "missing $f"
	done
	[ "$(stat -c %a /var/lib/testudo)" = 700 ] || fail "state directory mode"
	getent group testudo-admin >/dev/null || fail "no testudo-admin group"
	dpkg-query -W -f="\${Conffiles}\n" testudo | grep -q /etc/pam.d/testudo || fail "PAM service is not a conffile"

	# The service command line, as systemd would run it.
	. /etc/default/testudo
	cmd=$(sed -n "s/^ExecStart=//p" /lib/systemd/system/testudo.service | sed "s|\$TESTUDO_ARGS|$TESTUDO_ARGS|")
	HOME=/var/lib/testudo $cmd >/tmp/testudo.log 2>&1 &
	pid=$!
	python3 - <<PY || { cat /tmp/testudo.log; fail "service did not become ready"; }
import ssl, time, urllib.request
ctx = ssl._create_unverified_context()
deadline = time.time() + 30
while True:
    try:
        for path in ("/healthz", "/readyz"):
            urllib.request.urlopen("https://127.0.0.1:8443" + path, context=ctx, timeout=2).read()
        break
    except Exception as e:
        if time.time() > deadline:
            raise SystemExit("not ready: %s" % e)
        time.sleep(0.3)
PY
	grep -q "password:" /tmp/testudo.log || fail "no first-run password in the log"
	kill $pid; wait $pid 2>/dev/null || true
	[ -f /var/lib/testudo/config/config.log ] || fail "no configuration store"
	# Host commands as root find the installed storage without --storage.
	testudo user list | grep -q "testudo " || fail "testudo user list does not see the service users"

	dpkg -r testudo >/dev/null
	test ! -e /usr/bin/testudo || fail "binary left after remove"
	test -f /etc/pam.d/testudo || fail "conffile removed before purge"
	dpkg -P testudo >/dev/null
	test ! -e /etc/pam.d/testudo || fail "conffile left after purge"
	test -d /var/lib/testudo || fail "state removed on purge"
	echo "deb-install-test: ok ($DEB)"
'
