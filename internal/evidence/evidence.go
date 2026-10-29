// Package evidence defines the versioned data contract. Values remain attributed
// to individual sources; collection never resolves differing source statements.
package evidence

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = "0.3"

type Status string

const (
	OK            Status = "ok"
	Unknown       Status = "unknown"
	NotFound      Status = "not_found"
	NotApplicable Status = "not_applicable"
	FetchFailed   Status = "fetch_failed"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func CVE(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !cvePattern.MatchString(s) {
		return "", fmt.Errorf("invalid CVE ID: expected CVE-YYYY-NNNN...")
	}
	return s, nil
}

type Source struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	PublishedAt *string   `json:"published_at"`
	RetrievedAt time.Time `json:"retrieved_at"`
	Status      Status    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
}

// Fact is one value taken from one source response. SourcePointer is an
// RFC 6901 JSON Pointer into that response body; Original holds the value at
// the pointer when Value is a normalized or extracted form of it.
type Fact struct {
	ID            string          `json:"id"`
	Field         string          `json:"field"`
	Value         json.RawMessage `json:"value"`
	SourceIDs     []string        `json:"source_ids"`
	SourcePointer string          `json:"source_pointer"`
	Original      json.RawMessage `json:"original,omitempty"`
}
type Signal struct {
	Status    Status   `json:"status"`
	SourceIDs []string `json:"source_ids"`
	Score     *float64 `json:"score,omitempty"`
	AsOf      *string  `json:"as_of,omitempty"`
}
type Conflict struct {
	Field   string   `json:"field"`
	FactIDs []string `json:"fact_ids"`
	Reason  string   `json:"reason"`
}
type Document struct {
	SchemaVersion string     `json:"schema_version"`
	CVEID         string     `json:"cve_id"`
	State         Status     `json:"state"`
	FetchedAt     time.Time  `json:"fetched_at"`
	Sources       []Source   `json:"sources"`
	Facts         []Fact     `json:"facts"`
	CVSS          []string   `json:"cvss"`
	Affected      []string   `json:"affected"`
	Fixed         []string   `json:"fixed"`
	KEV           Signal     `json:"kev"`
	EPSS          Signal     `json:"epss"`
	Conflicts     []Conflict `json:"conflicts"`
	Warnings      []string   `json:"warnings"`
}

func New(id string, now time.Time) Document {
	return Document{SchemaVersion: SchemaVersion, CVEID: id, State: Unknown, FetchedAt: now.UTC(), Sources: []Source{}, Facts: []Fact{}, CVSS: []string{}, Affected: []string{}, Fixed: []string{}, KEV: Signal{Status: Unknown, SourceIDs: []string{}}, EPSS: Signal{Status: Unknown, SourceIDs: []string{}}, Conflicts: []Conflict{}, Warnings: []string{}}
}

// Pointer builds an RFC 6901 JSON Pointer from object keys and array indexes.
func Pointer(parts ...any) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("/")
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(fmt.Sprint(p)))
	}
	return b.String()
}

// Add records a value exactly as it appears at pointer in the source body.
func (d *Document) Add(field string, value any, source, pointer string) {
	d.AddNormalized(field, value, nil, source, pointer)
}

// AddNormalized records a value derived from original, which is kept when the
// two differ so readers can compare the normalization with the source text.
func (d *Document) AddNormalized(field string, value, original any, source, pointer string) {
	raw, _ := json.Marshal(value)
	f := Fact{ID: fmt.Sprintf("F%d", len(d.Facts)+1), Field: field, Value: raw, SourceIDs: []string{source}, SourcePointer: pointer}
	if original != nil {
		if o, _ := json.Marshal(original); string(o) != string(raw) {
			f.Original = o
		}
	}
	d.Facts = append(d.Facts, f)
	switch field {
	case "cvss":
		d.CVSS = append(d.CVSS, f.ID)
	case "affected":
		d.Affected = append(d.Affected, f.ID)
	case "fixed":
		d.Fixed = append(d.Fixed, f.ID)
	}
	if field != "description" {
		return
	}
	var current struct {
		Lang string `json:"lang"`
	}
	if json.Unmarshal(raw, &current) != nil || current.Lang == "" {
		return
	}
	for _, prior := range d.Facts[:len(d.Facts)-1] {
		var previous struct {
			Lang string `json:"lang"`
		}
		if json.Unmarshal(prior.Value, &previous) != nil || !strings.EqualFold(previous.Lang, current.Lang) {
			continue
		}
		if prior.Field == field && string(prior.Value) != string(raw) && prior.SourceIDs[0] != source {
			d.Conflicts = append(d.Conflicts, Conflict{Field: field, FactIDs: []string{prior.ID, f.ID}, Reason: "Source wording differs; semantic conflict requires human/Skill review."})
		}
	}
}

// Lookup resolves index IDs such as Document.Fixed to their facts.
func (d *Document) Lookup(ids []string) []Fact {
	facts := make([]Fact, 0, len(ids))
	for _, id := range ids {
		for _, f := range d.Facts {
			if f.ID == id {
				facts = append(facts, f)
			}
		}
	}
	return facts
}
