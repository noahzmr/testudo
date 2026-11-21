//go:build !linux

package flowattr

import "os"

func inodeOf(os.FileInfo) uint64 { return 0 }
