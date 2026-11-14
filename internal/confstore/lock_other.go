//go:build !linux

package confstore

import "os"

func lockFile(*os.File) error { return nil }
