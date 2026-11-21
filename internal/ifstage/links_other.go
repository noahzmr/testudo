//go:build !linux

package ifstage

import "errors"

func netlinkLinks(string) (Link, bool, error) {
	return Link{}, false, errors.New("interfaces are configured on Linux only")
}
