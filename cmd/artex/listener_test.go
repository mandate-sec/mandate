package main

import "testing"

func TestListenerPolicy(t *testing.T) {
	for _, tc := range []struct {
		address, acknowledgment string
		allowed                 bool
	}{
		{defaultListenAddr, "", true},
		{"127.0.0.2:8788", "", true},
		{"[::1]:8787", "", true},
		{"0.0.0.0:8787", "", false},
		{"[::]:8787", "", false},
		{":8787", "true", false},
		{"192.168.1.1:8788", "", false},
		{"localhost:8787", "", false},
		{":8787", "yes", true},
		{"", "yes", false},
		{"127.0.0.1:", "yes", false},
	} {
		if got := checkListener(tc.address, tc.acknowledgment) == nil; got != tc.allowed {
			t.Errorf("checkListener(%q, %q) allowed=%v, want %v", tc.address, tc.acknowledgment, got, tc.allowed)
		}
	}
}
