package sources

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

// anomaly copies the synthetic fixture and overlays testdata/anomalies/<name>.
func anomaly(t *testing.T, name string) evidence.Document {
	t.Helper()
	p := copyFixture(t)
	dir := filepath.Join("../../testdata/anomalies", name)
	es, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range es {
		b, e := os.ReadFile(filepath.Join(dir, f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(p, f.Name()), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	return d
}

func source(d evidence.Document, kind string) evidence.Source {
	for _, s := range d.Sources {
		if s.Kind == kind {
			return s
		}
	}
	return evidence.Source{}
}

func fields(d evidence.Document, field string) []evidence.Fact {
	facts := []evidence.Fact{}
	for _, f := range d.Facts {
		if f.Field == field {
			facts = append(facts, f)
		}
	}
	return facts
}

func warned(d evidence.Document, part string) bool {
	for _, w := range d.Warnings {
		if strings.Contains(w, part) {
			return true
		}
	}
	return false
}

func TestAnomalyFixtures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, evidence.Document)
	}{
		{"kev-count-mismatch", func(t *testing.T, d evidence.Document) {
			if s := source(d, "cisa_kev"); s.Status != evidence.FetchFailed || !strings.Contains(s.Reason, "count 3 does not match 1") || d.KEV.Status != evidence.Unknown {
				t.Fatal("truncated KEV catalog treated as complete", s, d.KEV)
			}
		}},
		{"kev-count-missing", func(t *testing.T, d evidence.Document) {
			if s := source(d, "cisa_kev"); s.Status != evidence.FetchFailed || d.KEV.Status != evidence.Unknown {
				t.Fatal("KEV without count treated as complete", s)
			}
		}},
		{"kev-count-fraction", func(t *testing.T, d evidence.Document) {
			if s := source(d, "cisa_kev"); s.Status != evidence.FetchFailed || s.Reason != "KEV catalog count is not a non-negative integer" || d.KEV.Status != evidence.Unknown {
				t.Fatal("fractional KEV count truncated into a match", s)
			}
		}},
		{"kev-count-negative", func(t *testing.T, d evidence.Document) {
			if s := source(d, "cisa_kev"); s.Status != evidence.FetchFailed || d.KEV.Status != evidence.Unknown {
				t.Fatal("negative KEV count accepted", s)
			}
		}},
		{"kev-entry-without-cve", func(t *testing.T, d evidence.Document) {
			if source(d, "cisa_kev").Status != evidence.FetchFailed || d.KEV.Status != evidence.Unknown || len(fields(d, "known_exploitation")) != 0 {
				t.Fatal("malformed KEV catalog produced a signal")
			}
		}},
		{"kev-duplicate-listing", func(t *testing.T, d evidence.Document) {
			if d.KEV.Status != evidence.OK || len(fields(d, "known_exploitation")) != 2 || !warned(d, "more than once") {
				t.Fatal("duplicate KEV listing not reported", d.Warnings)
			}
			if f := fields(d, "known_exploitation"); f[0].SourcePointer != "/vulnerabilities/0" || f[1].SourcePointer != "/vulnerabilities/1" {
				t.Fatal("KEV entry location lost", f)
			}
		}},
		{"nvd-id-only", func(t *testing.T, d evidence.Document) {
			if s := source(d, "nvd"); s.Status != evidence.FetchFailed || s.Reason != "NVD record lacks descriptions" {
				t.Fatal("empty NVD record treated as success", s)
			}
			b, _ := json.Marshal(d.Facts)
			if strings.Contains(string(b), "should-not-appear") || len(fields(d, "nvd_status")) != 0 {
				t.Fatal("empty NVD record produced facts")
			}
		}},
		{"nvd-total-mismatch", func(t *testing.T, d evidence.Document) {
			if s := source(d, "nvd"); s.Status != evidence.FetchFailed || !strings.Contains(s.Reason, "totalResults") {
				t.Fatal("partial NVD result treated as complete", s)
			}
		}},
		{"nvd-total-fraction", func(t *testing.T, d evidence.Document) {
			if s := source(d, "nvd"); s.Status != evidence.FetchFailed || s.Reason != "NVD totalResults is not a non-negative integer" {
				t.Fatal("fractional totalResults read as no NVD record", s)
			}
		}},
		{"nvd-total-missing", func(t *testing.T, d evidence.Document) {
			if s := source(d, "nvd"); s.Status != evidence.FetchFailed || len(fields(d, "nvd_status")) != 0 {
				t.Fatal("NVD response without totalResults accepted", s)
			}
		}},
		{"nvd-only-reserved", func(t *testing.T, d evidence.Document) {
			if d.State != evidence.Unknown || source(d, "nvd").Status != evidence.FetchFailed || warned(d, "NVD has a record") {
				t.Fatal("empty NVD record reported as usable", d.State, d.Warnings)
			}
		}},
		{"ghsa-withdrawn", func(t *testing.T, d evidence.Document) {
			if len(fields(d, "advisory_withdrawn")) != 1 || !warned(d, "withdrawn") {
				t.Fatal("withdrawn advisory not flagged", d.Warnings)
			}
			if f := fields(d, "advisory_severity"); len(f) != 1 || f[0].SourcePointer != "/severity" {
				t.Fatal("advisory severity lost", f)
			}
		}},
		{"ghsa-id-mismatch", func(t *testing.T, d evidence.Document) {
			if s := source(d, "ghsa"); s.Status != evidence.FetchFailed || s.Reason != "advisory GHSA ID mismatch" || len(d.Fixed) != 0 {
				t.Fatal("advisory for another GHSA accepted", s)
			}
		}},
		{"ghsa-id-missing", func(t *testing.T, d evidence.Document) {
			if s := source(d, "ghsa"); s.Status != evidence.FetchFailed || s.Reason != "advisory lacks GHSA ID" || len(d.Fixed) != 0 {
				t.Fatal("advisory without GHSA ID accepted", s, d.Fixed)
			}
		}},
		{"ghsa-id-wrong-type", func(t *testing.T, d evidence.Document) {
			if s := source(d, "ghsa"); s.Status != evidence.FetchFailed || s.Reason != "advisory lacks GHSA ID" || len(d.Fixed) != 0 {
				t.Fatal("advisory with malformed GHSA ID accepted", s, d.Fixed)
			}
		}},
		{"ghsa-duplicate-patch", func(t *testing.T, d evidence.Document) {
			if len(d.Fixed) != 1 {
				t.Fatal("same patched version recorded twice", d.Fixed)
			}
			cvss := d.Lookup(d.CVSS)
			if len(cvss) != 1 || cvss[0].SourcePointer != "/cvss_severities/cvss_v4" {
				t.Fatal("GHSA CVSS v4 lost or empty v3 recorded", cvss)
			}
			if w := fields(d, "weakness"); len(w) != 1 || w[0].SourcePointer != "/cwes/0" {
				t.Fatal("GHSA CWE lost", w)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := anomaly(t, tc.name)
			tc.check(t, d)
			assertFactsFromValidSources(t, d)
		})
	}
}

// Every fact must come from a successfully validated source and point into it.
func assertFactsFromValidSources(t *testing.T, d evidence.Document) {
	t.Helper()
	status := map[string]evidence.Status{}
	for _, s := range d.Sources {
		status[s.ID] = s.Status
	}
	for _, f := range d.Facts {
		if len(f.SourceIDs) != 1 || status[f.SourceIDs[0]] != evidence.OK || !strings.HasPrefix(f.SourcePointer, "/") {
			t.Fatalf("fact %s is not traceable to a valid source: %+v", f.ID, f)
		}
	}
}

func TestBaselineTraceability(t *testing.T) {
	dir := "../../testdata/CVE-2026-109618"
	d, e := (&Collector{Fixture: dir}).Fetch(context.Background(), "CVE-2026-109618")
	if e != nil {
		t.Fatal(e)
	}
	assertFactsFromValidSources(t, d)
	bodies := map[string]any{}
	for key, id := range map[string]string{"cve": "S1", "nvd": "S2", "GHSA-w8hw-w9fx-j79w": "S3", "kev": "S8"} {
		b, e := os.ReadFile(filepath.Join(dir, key+".json"))
		if e != nil {
			t.Fatal(e)
		}
		var v any
		if e := json.Unmarshal(b, &v); e != nil {
			t.Fatal(e)
		}
		bodies[id] = v
	}
	for _, f := range d.Facts {
		at, ok := resolve(bodies[f.SourceIDs[0]], f.SourcePointer)
		if !ok {
			t.Fatalf("%s: pointer %s does not resolve", f.ID, f.SourcePointer)
		}
		want := f.Value
		if f.Original != nil {
			want = f.Original
		}
		var expected any
		json.Unmarshal(want, &expected)
		a, _ := json.Marshal(at)
		b, _ := json.Marshal(expected)
		if string(a) != string(b) {
			t.Fatalf("%s: value at %s differs from recorded original", f.ID, f.SourcePointer)
		}
	}
	for _, f := range d.Lookup(d.Fixed) {
		if f.Original == nil {
			t.Fatal("normalized fixed version lost its source text", f.ID)
		}
	}
}

func resolve(v any, pointer string) (any, bool) {
	for _, part := range strings.Split(pointer, "/")[1:] {
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
		switch node := v.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			i, e := strconv.Atoi(part)
			if e != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			v = node[i]
		default:
			return nil, false
		}
	}
	return v, true
}
