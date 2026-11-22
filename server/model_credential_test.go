package server

import (
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestStoredModelKeyBoundToDestination(t *testing.T) {
	saved := agent.ConfigFrom("openai", "old", "https://provider.invalid/v1", "test-key", "")
	for _, tc := range []struct {
		provider, base, proxy, want string
	}{
		{"openai", saved.BaseURL, "", saved.APIKey},
		{"openai", "https://other.invalid/v1", "", ""},
		{"openai", saved.BaseURL, "http://proxy.invalid", ""},
		{"anthropic", saved.BaseURL, "", ""},
	} {
		requested := agent.ConfigFrom(tc.provider, "new", tc.base, "", tc.proxy)
		if got := storedModelKey(requested, saved); got != tc.want {
			t.Errorf("unexpected key reuse for %s %s %s", tc.provider, tc.base, tc.proxy)
		}
	}
}
