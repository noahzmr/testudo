package svcrender

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/noahzmr/testudo/internal/model"
)

// snmpd renders net-snmp's agent for SNMPv3 only: no community, one
// read-only user each with SHA-256 and AES, a view of the whole tree,
// listening on the interfaces' addresses. Its engine id comes from the
// node, so it stays the same across restarts.
func (r *renderer) snmpd(res *Result) string {
	a := r.snmp
	q := func(v string) string { return `"` + v + `"` }
	// One token per value: no line breaks, and no quotes or backslashes,
	// which net-snmp's parser treats on its own terms.
	one := func(v string) bool { return !strings.ContainsAny(v, "\n\r\x00\"\\") }
	var b strings.Builder
	b.WriteString(header("net-snmp agent, SNMPv3 only"))
	var listen []string
	for _, iface := range a.Interfaces {
		for _, six := range []bool{false, true} {
			if addr := r.addrOn(iface, six, nil); addr != "" {
				if six {
					listen = append(listen, "udp6:["+addr+"]:161")
				} else {
					listen = append(listen, "udp:"+addr+":161")
				}
			}
		}
	}
	if len(listen) == 0 {
		r.fail("snmp agent %q: none of its interfaces has an address in the model", a.Name)
		return ""
	}
	fmt.Fprintf(&b, "agentAddress %s\n", strings.Join(listen, ","))
	sum := sha256.Sum256([]byte(r.opt.NodeID))
	fmt.Fprintf(&b, "exactEngineID 0x80001f8804%s\n", hex.EncodeToString(sum[:12]))
	fmt.Fprintf(&b, "persistentDir %s\n", filepath.Join(r.opt.Dir, "snmp"))
	b.WriteString("dontLogTCPWrappersConnects yes\nview all included .1\n")
	if a.Location != "" && one(a.Location) {
		fmt.Fprintf(&b, "sysLocation %s\n", a.Location)
	}
	if a.Contact != "" && one(a.Contact) {
		fmt.Fprintf(&b, "sysContact %s\n", a.Contact)
	}
	n := 0
	for _, ref := range a.Users {
		o, ok := r.st.Get(model.KindSNMPUser, ref.ID)
		if !ok {
			continue
		}
		u := o.(*model.SNMPUser)
		if !one(u.AuthPassword) || !one(u.PrivPassword) {
			r.fail("snmp user %q: passwords are one line without quotes or backslashes", u.Name)
			continue
		}
		fmt.Fprintf(&b, "createUser %s SHA-256 %s AES %s\n", u.Username, q(u.AuthPassword), q(u.PrivPassword))
		fmt.Fprintf(&b, "rouser %s priv -V all\n", u.Username)
		n++
	}
	if n == 0 {
		r.fail("snmp agent %q has no user", a.Name)
		return ""
	}
	res.Open.SNMP = sortedUnique(a.Interfaces)
	res.Open.SNMPFrom = sortedUnique(a.AllowFrom)
	return b.String()
}
