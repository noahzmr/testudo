//go:build !linux

package nflog

import "errors"

// Open is only available on Linux.
func Open(uint16) (int, error) { return -1, errors.New("nflog is only available on Linux") }

// Reader is only available on Linux.
type Reader struct{}

func NewReader(int) *Reader            { return &Reader{} }
func (*Reader) Read() ([]Entry, error) { return nil, errors.New("nflog is only available on Linux") }
func (*Reader) Close() error           { return nil }
