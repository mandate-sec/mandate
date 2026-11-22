package server

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSessionJWTPolicy(t *testing.T) {
	key := []byte("unit-test-key")
	token, err := signJWT(key)
	if err != nil || !verifyJWT(token, key) || verifyJWT(token, []byte("different-key")) {
		t.Fatalf("issued token verification failed: %v", err)
	}
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	past := jwt.NewNumericDate(time.Now().Add(-time.Hour))
	for _, tc := range []struct {
		subject string
		method  jwt.SigningMethod
		expiry  *jwt.NumericDate
	}{
		{"ARTEX", jwt.SigningMethodHS256, nil},
		{"ARTEX", jwt.SigningMethodHS256, past},
		{"other", jwt.SigningMethodHS256, future},
		{"ARTEX", jwt.SigningMethodHS384, future},
	} {
		raw, err := jwt.NewWithClaims(tc.method, jwt.RegisteredClaims{Subject: tc.subject, ExpiresAt: tc.expiry}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if verifyJWT(raw, key) {
			t.Errorf("accepted invalid session: %+v", tc)
		}
	}
}

func TestPasswordChangeRevokesPreviousGeneration(t *testing.T) {
	key := []byte("fixture signing key")
	for _, previous := range []string{"", "previous-change"} {
		token, err := signJWT(sessionSigningKey(key, previous))
		if err != nil {
			t.Fatal(err)
		}
		if !verifyJWT(token, sessionSigningKey(key, previous)) || verifyJWT(token, sessionSigningKey(key, "new-change")) {
			t.Fatal("session must validate exclusively under its original generation")
		}
	}
}
