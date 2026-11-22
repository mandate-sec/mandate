package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

func validSetupToken(token, configuredDigest string) bool {
	if len(token) != 64 || len(configuredDigest) != sha256.Size*2 {
		return false
	}
	digest, err := hex.DecodeString(configuredDigest)
	if err != nil {
		return false
	}
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(actual[:], digest) == 1
}
