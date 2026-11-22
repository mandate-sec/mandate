//go:build !unix

package server

import "os"

// The installation owner provisions the key directory ACL on Windows.
func sessionKeyOwned(os.FileInfo) bool { return true }
