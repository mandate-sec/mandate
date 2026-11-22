package server

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestSetupToken(t *testing.T) {
	token := strings.Repeat("a", 64)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	for _, tc := range []struct {
		name, token, digest string
		want                bool
	}{
		{"valid", token, digest, true},
		{"unconfigured", token, "", false},
		{"missing token", "", digest, false},
		{"wrong token", strings.Repeat("b", 64), digest, false},
		{"malformed digest", token, strings.Repeat("x", 64), false},
		{"digest used as token", digest, digest, false},
	} {
		if got := validSetupToken(tc.token, tc.digest); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}
