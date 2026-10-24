package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestOutputPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0, 0600, 0640, 0644} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "evidence.json")
			if mode != 0 {
				if e := os.WriteFile(p, []byte("old"), mode); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(p, mode); e != nil {
					t.Fatal(e)
				}
			}
			var out, err bytes.Buffer
			if n := run(context.Background(), []string{"fetch", "CVE-2026-0001", "--fixture", "../../testdata/synthetic", "--output", p}, &out, &err); n != 0 {
				t.Fatal(n, &err)
			}
			want := mode
			if want == 0 {
				want = 0644
			}
			info, e := os.Stat(p)
			if e != nil {
				t.Fatal(e)
			}
			if info.Mode().Perm() != want {
				t.Fatalf("got %o want %o", info.Mode().Perm(), want)
			}
		})
	}
}

func overlay(t *testing.T, dirs ...string) string {
	t.Helper()
	p := t.TempDir()
	for _, dir := range dirs {
		es, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, f := range es {
			b, e := os.ReadFile(filepath.Join(dir, f.Name()))
			if e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(p, f.Name()), b, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	return p
}

func TestEmptyNVDIsNotUsable(t *testing.T) {
	p := overlay(t, "../../testdata/synthetic", "../../testdata/anomalies/nvd-only-reserved")
	var out, err bytes.Buffer
	if n := run(context.Background(), []string{"fetch", "CVE-2026-0001", "--fixture", p}, &out, &err); n != 1 || !json.Valid(out.Bytes()) {
		t.Fatalf("NVD record without content counted as usable: %d %s", n, &err)
	}
	// A reserved CVE with a substantive NVD record remains a partial success.
	p = overlay(t, "../../testdata/synthetic")
	if e := os.WriteFile(filepath.Join(p, "cve.json"), []byte(`{"cveMetadata":{"cveId":"CVE-2026-0001","state":"RESERVED"}}`), 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if n := run(context.Background(), []string{"fetch", "CVE-2026-0001", "--fixture", p}, &out, &err); n != 0 {
		t.Fatalf("NVD evidence discarded for reserved CVE: %d %s", n, &err)
	}
}
