package journal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreatePublishesOneCompletePlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")
	if err := Create(dir, path, make(chan int)); err == nil {
		t.Fatal("accepted unserializable plan")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("failed write left files: %v %v", entries, err)
	}
	results := make(chan error, 8)
	for i := range cap(results) {
		go func() { results <- Create(dir, path, i) }()
	}
	winners := 0
	for range cap(results) {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful publishers: %d", winners)
	}
	raw, err := os.ReadFile(path)
	var value int
	if err != nil || json.Unmarshal(raw, &value) != nil || value < 0 || value >= cap(results) {
		t.Fatal("invalid published plan")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("unexpected stage contents: %v %v", entries, err)
	}
}
