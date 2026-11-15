//go:build linux

package privsep

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// RaiseAmbientNetAdmin makes CAP_NET_ADMIN survive the execution of a program
// that has no file capabilities, for the calling thread and the children it
// forks. The capability must already be permitted. Callers must have locked
// the goroutine to its thread.
func RaiseAmbientNetAdmin() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	const bit = uint32(1) << unix.CAP_NET_ADMIN
	if data[0].Permitted&bit == 0 {
		return fmt.Errorf("CAP_NET_ADMIN is not permitted")
	}
	// Ambient requires the capability to be inheritable as well.
	data[0].Inheritable |= bit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_ADMIN, 0, 0); err != nil {
		return fmt.Errorf("raise ambient: %w", err)
	}
	return nil
}

// KeepOnlyBindService reduces the calling thread to CAP_NET_BIND_SERVICE,
// made ambient so that the program executed next can bind low ports and do
// nothing else privileged. Without that capability it clears everything,
// which leaves a process that can only bind high ports. Callers must have
// locked the goroutine to its thread.
func KeepOnlyBindService() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	const bit = uint32(1) << unix.CAP_NET_BIND_SERVICE
	keep := data[0].Permitted & bit
	data[0].Permitted, data[0].Effective, data[0].Inheritable = keep, keep, keep
	data[1] = unix.CapUserData{}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if keep != 0 {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_BIND_SERVICE, 0, 0); err != nil {
			return fmt.Errorf("raise ambient: %w", err)
		}
	}
	return nil
}
