//go:build !(linux && cgo && pam)

package pamauth

const available = false

func authenticate(Request) (string, error) { return "", ErrUnavailable }
