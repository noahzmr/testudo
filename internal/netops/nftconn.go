package netops

import (
	"errors"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nftBufferBytes is the socket buffer the nftables connection asks for. The
// kernel rejects a netlink batch larger than the socket's send buffer with
// EMSGSIZE ("message too long"), and a whole table of a few hundred rules is
// well past the 208 KiB default - so, exactly like `nft` (mnl_set_sndbuffer),
// the buffer is raised before the batch goes out. Buffer limits are accounting
// caps, not up-front allocations.
const nftBufferBytes = 64 << 20

// nftConn opens an nftables connection with enlarged send/receive buffers.
// Every netops nftables access goes through here so large tables apply (and
// dump) in one piece.
func nftConn() (*nftables.Conn, error) {
	return nftables.New(nftables.WithSockOptions(raiseNetlinkBuffers))
}

// raiseNetlinkBuffers sets SO_SNDBUFFORCE / SO_RCVBUFFORCE (CAP_NET_ADMIN lets
// them exceed net.core.wmem_max / rmem_max, which is the privileged helper's
// normal situation) and falls back to the unforced options, capped by the
// sysctls, when the process lacks the capability. Failing to raise a buffer
// is not fatal - small tables still work with the defaults.
func raiseNetlinkBuffers(c *netlink.Conn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return raw.Control(func(fd uintptr) {
		for _, pair := range [][2]int{
			{unix.SO_SNDBUFFORCE, unix.SO_SNDBUF},
			{unix.SO_RCVBUFFORCE, unix.SO_RCVBUF},
		} {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, pair[0], nftBufferBytes); err != nil &&
				(errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, pair[1], nftBufferBytes)
			}
		}
	})
}
