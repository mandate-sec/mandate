package report

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsCSVFormulaPrefixes(t *testing.T) {
	f := &db.DBFinding{ID: 42, Name: "=1+1", VulnClass: "  +2", Status: "@test", Severity: "-1", TaskDescription: "\ufeff＝2", Summary: "ordinary, quoted \"text\""}
	data := strings.TrimPrefix(string(FindingsCSV([]*db.DBFinding{f})), "\ufeff")
	rows, err := csv.NewReader(strings.NewReader(data)).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[1]) != 10 {
		t.Fatalf("unexpected CSV: %v, %v", rows, err)
	}
	for col, want := range map[int]string{0: "42", 1: "'=1+1", 2: "'  +2", 3: "'-1", 4: "'@test", 5: "'\ufeff＝2", 7: f.Summary, 8: "0"} {
		if got := rows[1][col]; got != want {
			t.Errorf("column %d = %q, want %q", col, got, want)
		}
	}
}
