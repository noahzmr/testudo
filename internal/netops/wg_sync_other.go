//go:build !linux

package netops

import "errors"

func (w *Writer) syncWGDirect(WGSpec) error {
	return errors.New("wireguard sync is only supported on Linux")
}
