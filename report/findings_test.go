package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestFindingFilenameLongTitles(t *testing.T) {
	title := strings.Repeat("界", 60)
	first := FindingFilename(&db.DBFinding{ID: 10, Name: title})
	second := FindingFilename(&db.DBFinding{ID: 11, Name: title})
	if strings.EqualFold(first, second) || !utf8.ValidString(first) || len(first) > 124 || !strings.HasSuffix(first, ".md") {
		t.Fatalf("invalid or colliding archive names: %q and %q", first, second)
	}
}

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
