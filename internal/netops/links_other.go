//go:build !linux

package netops

import "errors"

func (w *Writer) syncLinksDirect(LinksSpec) error {
	return errors.New("links are configured on Linux only")
}
