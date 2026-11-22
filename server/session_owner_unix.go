//go:build unix

package server

import (
	"os"
	"syscall"
)

// Check the opened descriptor without following a substituted symlink or waiting on a FIFO.
const sessionKeyOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func sessionKeyOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}
