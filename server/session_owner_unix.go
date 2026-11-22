//go:build unix

package server

import (
	"os"
	"syscall"
)

func sessionKeyOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}
