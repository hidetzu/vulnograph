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

const SchemaVersion = "0.1"

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
type Fact struct {
	ID              string          `json:"id"`
	Field           string          `json:"field"`
	Value           json.RawMessage `json:"value"`
	SourceIDs       []string        `json:"source_ids"`
	EvidenceExcerpt string          `json:"evidence_excerpt"`
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
	CVSS          []Fact     `json:"cvss"`
	Affected      []Fact     `json:"affected"`
	Fixed         []Fact     `json:"fixed"`
	KEV           Signal     `json:"kev"`
	EPSS          Signal     `json:"epss"`
	Conflicts     []Conflict `json:"conflicts"`
	Warnings      []string   `json:"warnings"`
}

func New(id string, now time.Time) Document {
	return Document{SchemaVersion: SchemaVersion, CVEID: id, State: Unknown, FetchedAt: now.UTC(), Sources: []Source{}, Facts: []Fact{}, CVSS: []Fact{}, Affected: []Fact{}, Fixed: []Fact{}, KEV: Signal{Status: Unknown, SourceIDs: []string{}}, EPSS: Signal{Status: Unknown, SourceIDs: []string{}}, Conflicts: []Conflict{}, Warnings: []string{}}
}
func (d *Document) Add(field string, value any, source string) {
	raw, _ := json.Marshal(value)
	f := Fact{ID: fmt.Sprintf("F%d", len(d.Facts)+1), Field: field, Value: raw, SourceIDs: []string{source}, EvidenceExcerpt: "Structured source field: " + field}
	d.Facts = append(d.Facts, f)
	switch field {
	case "cvss":
		d.CVSS = append(d.CVSS, f)
	case "affected":
		d.Affected = append(d.Affected, f)
	case "fixed":
		d.Fixed = append(d.Fixed, f)
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
