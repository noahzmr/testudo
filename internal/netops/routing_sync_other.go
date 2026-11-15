//go:build !linux

package netops

import "errors"

func (w *Writer) syncRoutingDirect(RoutingSpec) error {
	return errors.New("routing sync is only supported on Linux")
}
