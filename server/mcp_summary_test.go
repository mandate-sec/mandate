package server

import (
	"database/sql"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	_ "modernc.org/sqlite"
)

func TestMCPPickerSummary(t *testing.T) {
	store, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetMaxOpenConns(1)
	// The picker query must work without access to any configuration columns.
	if _, err := store.Exec("CREATE TABLE mcp_servers(id INTEGER, name TEXT, transport TEXT)"); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: &db.DB{DB: store}}}
	check := func(want string) {
		t.Helper()
		w := httptest.NewRecorder()
		s.pgListMCP(w, httptest.NewRequest("GET", "/api/mcp?view=summary", nil))
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != want {
			t.Fatalf("summary: status %d, response %s", w.Code, w.Body.String())
		}
	}
	check(`{"servers":[]}`)
	if _, err := store.Exec("INSERT INTO mcp_servers VALUES (7,'Example','http')"); err != nil {
		t.Fatal(err)
	}
	check(`{"servers":[{"id":7,"name":"Example","transport":"http"}]}`)
}
