package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsExportSeverityOrder(t *testing.T) {
	older := time.Unix(1, 0)
	newer := time.Unix(2, 0)
	findings := []*db.DBFinding{
		{ID: 1, Severity: "custom", CreatedAt: newer},
		{ID: 2, Severity: " high ", CreatedAt: older},
		{ID: 3, Severity: "critical", CreatedAt: older},
		{ID: 4, Severity: "info", CreatedAt: older},
	}
	data := strings.TrimPrefix(string(FindingsCSV(findings)), "\ufeff")
	rows, err := csv.NewReader(strings.NewReader(data)).ReadAll()
	if err != nil || len(rows) != 5 {
		t.Fatalf("unexpected CSV: %v, %v", rows, err)
	}
	for i, want := range []string{"3", "2", "1", "4"} {
		if got := rows[i+1][0]; got != want {
			t.Errorf("row %d finding ID = %q, want %q", i+1, got, want)
		}
	}
	markdown := FindingsMarkdown(findings, newer)
	for _, want := range []string{"| 高危 | 1 |", "| 信息/其他 | 2 |"} {
		if !strings.Contains(markdown, want) {
			t.Errorf("summary is missing %q", want)
		}
	}
}

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
