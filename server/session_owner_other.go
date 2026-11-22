//go:build !unix

package server

import "os"

const sessionKeyOpenFlags = 0

// The installation owner provisions the key directory ACL on Windows.
func sessionKeyOwned(os.FileInfo) bool { return true }
