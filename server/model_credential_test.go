package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestModelListPrivateErrors(t *testing.T) {
	const marker = "private-provider-detail"
	for _, tc := range []struct {
		name, proxy string
		status      int
		body        string
		wantHTTP    bool
	}{
		{"provider error", "", 401, marker, true},
		{"invalid proxy", "http://%zz", 200, "", false},
		{"valid list", "", 200, `{"data":[{"id":"model-a"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called <- struct{}{}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			body, err := json.Marshal(map[string]string{"provider": "openai", "base_url": srv.URL, "api_key": "test", "proxy": tc.proxy})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			new(Server).pgListModels(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
			var result struct {
				OK     bool
				Error  string
				Models []string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (len(called) > 0) != tc.wantHTTP || strings.Contains(w.Body.String(), marker) {
				t.Fatal("unexpected delivery or private response text")
			}
			if tc.status == 401 && !strings.Contains(result.Error, "401") {
				t.Fatal("missing provider status")
			}
			if tc.proxy != "" && (result.OK || result.Error == "") {
				t.Fatal("invalid proxy accepted")
			}
			if tc.proxy == "" && tc.status == 200 && (!result.OK || len(result.Models) != 1 || result.Models[0] != "model-a") {
				t.Fatal("valid model list lost")
			}
		})
	}
}

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
