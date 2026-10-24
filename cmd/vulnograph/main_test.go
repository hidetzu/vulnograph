package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

func TestCLI(t *testing.T) {
	for _, args := range [][]string{nil, {"fetch"}, {"fetch", "oops"}, {"fetch", "CVE-2026-0001", "--format", "html"}, {"fetch", "CVE-2026-0001", "extra"}} {
		var out, err bytes.Buffer
		if n := run(context.Background(), args, &out, &err); n != 2 {
			t.Fatalf("%v: %d", args, n)
		}
	}
	var out, err bytes.Buffer
	if n := run(context.Background(), []string{"fetch", "CVE-2026-0001", "--fixture", "../../testdata/synthetic"}, &out, &err); n != 0 {
		t.Fatalf("%d %s", n, &err)
	}
	var d evidence.Document
	if e := json.Unmarshal(out.Bytes(), &d); e != nil || d.CVEID != "CVE-2026-0001" {
		t.Fatal("invalid JSON", e)
	}
	p := filepath.Join(t.TempDir(), "nested", "evidence.json")
	out.Reset()
	if n := run(context.Background(), []string{"fetch", "CVE-2026-0001", "--fixture", "../../testdata/synthetic", "--output", p}, &out, &err); n != 0 {
		t.Fatal(n, &err)
	}
	if b, e := os.ReadFile(p); e != nil || len(b) == 0 || out.Len() != 0 {
		t.Fatal("file output failed", e)
	}
}
func TestMissingSourcesExit(t *testing.T) {
	p := t.TempDir()
	if e := os.WriteFile(filepath.Join(p, "manifest.json"), []byte(`{"cve_id":"CVE-2026-0001","fetched_at":"2026-10-24T00:00:00Z"}`), 0600); e != nil {
		t.Fatal(e)
	}
	var out, err bytes.Buffer
	if n := run(context.Background(), []string{"fetch", "CVE-2026-0001", "--fixture", p}, &out, &err); n != 1 || !json.Valid(out.Bytes()) {
		t.Fatalf("missing failure evidence: %d %s", n, &err)
	}
}
