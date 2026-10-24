package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

type obj = map[string]any

func object(v any) obj { m, _ := v.(map[string]any); return m }
func list(v any) []any { a, _ := v.([]any); return a }
func str(v any) string { s, _ := v.(string); return s }
func (c *Collector) load(ctx context.Context, d *evidence.Document, key, kind, raw string) (any, string) {
	s := evidence.Source{ID: fmt.Sprintf("S%d", len(d.Sources)+1), Kind: kind, Title: kind, URL: raw, RetrievedAt: d.FetchedAt, Status: evidence.FetchFailed}
	r := c.get(ctx, key, raw)
	var v any
	if c.Fixture == "" {
		s.RetrievedAt = time.Now().UTC()
	}
	switch {
	case r.Reason != "":
		s.Reason = r.Reason
	case r.Code == 404:
		s.Status = evidence.NotFound
		s.Reason = "HTTP 404; does not distinguish reserved from nonexistent CVE"
	case r.Code != 200:
		s.Reason = fmt.Sprintf("HTTP %d", r.Code)
	case json.Unmarshal(r.Body, &v) != nil:
		s.Reason = "invalid JSON response"
	default:
		s.Status = evidence.OK
		s.SHA256 = digest(r.Body)
	}
	if s.Status == evidence.OK && v == nil {
		s.Status = evidence.FetchFailed
		s.Reason = "null JSON response"
	}
	if s.Status == evidence.OK {
		m := object(v)
		published := str(m["published_at"])
		if kind == "cve_record" {
			published = str(object(m["cveMetadata"])["datePublished"])
		}
		if published != "" {
			s.PublishedAt = &published
		}
	}
	d.Sources = append(d.Sources, s)
	if s.Status != evidence.OK {
		d.Warnings = append(d.Warnings, s.ID+": "+string(s.Status)+": "+s.Reason)
	}
	if s.Status != evidence.OK {
		return nil, s.ID
	}
	return v, s.ID
}
func fail(d *evidence.Document, id, why string) {
	for i := range d.Sources {
		if d.Sources[i].ID == id {
			d.Sources[i].Status = evidence.FetchFailed
			d.Sources[i].Reason = why
			d.Warnings = append(d.Warnings, id+": "+why)
		}
	}
}
func (c *Collector) Fetch(ctx context.Context, input string) (evidence.Document, error) {
	id, e := evidence.CVE(input)
	if e != nil {
		return evidence.Document{}, e
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	if c.Client == nil {
		c.Client = NewClient()
	}
	if c.Fixture != "" {
		b, e := os.ReadFile(filepath.Join(c.Fixture, "manifest.json"))
		if e != nil {
			return evidence.Document{}, fmt.Errorf("fixture manifest unavailable")
		}
		var m struct {
			CVEID     string    `json:"cve_id"`
			FetchedAt time.Time `json:"fetched_at"`
		}
		if json.Unmarshal(b, &m) != nil || m.CVEID != id || m.FetchedAt.IsZero() {
			return evidence.Document{}, fmt.Errorf("fixture manifest must match CVE and provide fetched_at")
		}
		now = m.FetchedAt.UTC()
	}
	d := evidence.New(id, now)
	v, s := c.load(ctx, &d, "cve", "cve_record", "https://cveawg.mitre.org/api/cve/"+id)
	record := object(v)
	meta := object(record["cveMetadata"])
	if v != nil {
		if str(meta["cveId"]) != id {
			fail(&d, s, "CVE response ID mismatch")
		} else {
			state := str(meta["state"])
			cna := object(object(record["containers"])["cna"])
			valid := state == "PUBLISHED" || state == "REJECTED" || state == "RESERVED"
			if state == "PUBLISHED" {
				hasDescription := false
				for _, entry := range list(cna["descriptions"]) {
					if strings.TrimSpace(str(object(entry)["value"])) != "" {
						hasDescription = true
					}
				}
				if !hasDescription {
					fail(&d, s, "published CVE lacks descriptions")
					valid = false
				}
			}
			if valid {
				d.Add("publication_state", state, s)
			}
			switch state {
			case "PUBLISHED":
				if valid {
					d.State = evidence.OK
				}
			case "REJECTED":
				d.State = evidence.NotApplicable
			case "RESERVED":
				d.State = evidence.Unknown
			default:
				fail(&d, s, "unrecognized publication state")
			}
			if state == "PUBLISHED" && valid {
				addDescriptions(&d, cna["descriptions"], s)
				for _, a := range list(cna["affected"]) {
					d.Add("affected", a, s)
				}
				for _, m := range list(cna["metrics"]) {
					d.Add("cvss", m, s)
				}
				for _, p := range list(cna["problemTypes"]) {
					d.Add("weakness", p, s)
				}
				for _, r := range list(cna["references"]) {
					addReference(&d, object(r)["url"], s)
				}
			}
		}
	} else if d.Sources[0].Status == evidence.NotFound {
		d.State = evidence.NotFound
	}
	v, s = c.load(ctx, &d, "nvd", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+id)
	if v != nil {
		n := object(v)
		items, valid := n["vulnerabilities"].([]any)
		idsValid := true
		for _, item := range items {
			if str(object(object(item)["cve"])["id"]) != id {
				idsValid = false
			}
		}

		if !valid {
			fail(&d, s, "missing NVD vulnerabilities array")
		} else if !idsValid {
			fail(&d, s, "NVD response ID mismatch")
		} else if len(items) == 0 {
			d.Sources[len(d.Sources)-1].Status = evidence.NotFound
			d.Warnings = append(d.Warnings, s+": no NVD record")
		} else {
			for _, item := range items {
				r := object(object(item)["cve"])
				if d.State == evidence.NotFound || d.State == evidence.Unknown {
					d.Warnings = append(d.Warnings, "NVD has a record; official CVE publication state remains unconfirmed")
				}
				d.Add("nvd_status", r["vulnStatus"], s)
				addDescriptions(&d, r["descriptions"], s)
				if m := r["metrics"]; m != nil {
					d.Add("cvss", m, s)
				}
				if a := r["configurations"]; a != nil {
					d.Add("affected", a, s)
				}
				for _, w := range list(r["weaknesses"]) {
					d.Add("weakness", w, s)
				}
				for _, r := range list(r["references"]) {
					addReference(&d, object(r)["url"], s)
				}
			}
		}
	}
	// Only repository advisory API URLs derived from recognized GitHub references
	// are fetched. Other references remain visible with a reason.
	refs := append([]evidence.Fact(nil), d.Facts...)
	seen := map[string]bool{}
	fetchedReferences := 0
	for _, f := range refs {
		if f.Field != "reference" {
			continue
		}
		var raw string
		json.Unmarshal(f.Value, &raw)
		if seen[raw] {
			continue
		}
		seen[raw] = true
		api, key := advisoryURL(raw)
		if api == "" {
			d.Sources = append(d.Sources, evidence.Source{ID: fmt.Sprintf("S%d", len(d.Sources)+1), Kind: "reference", Title: "Unfetched reference", URL: raw, RetrievedAt: now, Status: evidence.Unknown, Reason: "Reference retained; unsupported adapter or unverified vendor"})
			continue
		}
		if fetchedReferences >= 32 {
			d.Sources = append(d.Sources, evidence.Source{ID: fmt.Sprintf("S%d", len(d.Sources)+1), Kind: "reference", Title: "Unfetched reference", URL: raw, RetrievedAt: now, Status: evidence.Unknown, Reason: "Reference fetch limit reached"})
			d.Warnings = append(d.Warnings, "reference fetch limit reached")
			continue
		}
		fetchedReferences++
		v, s = c.load(ctx, &d, key, "ghsa", api)
		if v == nil {
			continue
		}
		a := object(v)
		if str(a["cve_id"]) != id {
			fail(&d, s, "advisory CVE mismatch")
			continue
		}
		if summary := str(a["summary"]); summary != "" {
			d.Add("advisory_summary", summary, s)
		}
		if body := str(a["description"]); body != "" {
			d.Add("advisory_description", body, s)
		}
		for _, v := range list(a["vulnerabilities"]) {
			if patched := str(object(v)["patched_versions"]); patched != "" {
				d.Add("fixed", obj{"package": object(v)["package"], "version": patched}, s)
			}
			d.Add("affected", v, s)
			fixed := str(object(v)["first_patched_version"])
			if fixed == "" {
				fixed = str(object(object(v)["first_patched_version"])["identifier"])
			}
			if fixed != "" {
				d.Add("fixed", obj{"package": object(v)["package"], "version": fixed}, s)
			}
		}
	}
	v, s = c.load(ctx, &d, "kev", "cisa_kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	d.KEV.SourceIDs = []string{s}
	if v != nil {
		k := object(v)
		items, valid := k["vulnerabilities"].([]any)
		if !valid || str(k["catalogVersion"]) == "" {
			fail(&d, s, "invalid KEV catalog")
		} else {
			d.KEV.Status = evidence.NotFound
			for _, item := range items {
				r := object(item)
				if str(r["cveID"]) == id {
					d.KEV.Status = evidence.OK
					d.Add("known_exploitation", r, s)
				}
			}
		}
	}
	v, s = c.load(ctx, &d, "epss", "first_epss", "https://api.first.org/data/v1/epss?cve="+id)
	d.EPSS.SourceIDs = []string{s}
	if v != nil {
		items, valid := object(v)["data"].([]any)
		if !valid {
			fail(&d, s, "invalid EPSS data")
		} else if len(items) == 0 {
			d.EPSS.Status = evidence.NotFound
		} else {
			r := object(items[0])
			score, err := strconv.ParseFloat(str(r["epss"]), 64)
			date := str(r["date"])
			_, dateErr := time.Parse("2006-01-02", date)
			if str(r["cve"]) != id || err != nil || !(score >= 0 && score <= 1) || dateErr != nil {
				fail(&d, s, "invalid EPSS ID, score or date")
			} else {
				d.EPSS.Status = evidence.OK
				d.EPSS.Score = &score
				d.EPSS.AsOf = &date
			}
		}
	}
	for _, s := range d.Sources {
		if s.Status != evidence.OK && s.Kind != "reference" {
			d.Warnings = append(d.Warnings, "Partial evidence: review all source statuses before drawing conclusions")
			break
		}
	}
	seenWarnings := map[string]bool{}
	warnings := []string{}
	for _, warning := range d.Warnings {
		if !seenWarnings[warning] {
			warnings = append(warnings, warning)
			seenWarnings[warning] = true
		}
	}
	d.Warnings = warnings
	return d, nil
}
func addDescriptions(d *evidence.Document, v any, s string) {
	for _, item := range list(v) {
		r := object(item)
		value := str(r["value"])
		if value != "" {
			d.Add("description", obj{"lang": r["lang"], "value": value}, s)
		}
	}
}
func addReference(d *evidence.Document, v any, s string) {
	if raw := cleanURL(str(v)); raw != "" {
		d.Add("reference", raw, s)
	}
}

var ghsaID = regexp.MustCompile(`^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`)
var repoName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func advisoryURL(raw string) (string, string) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return "", ""
	}
	p := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(p) == 2 && p[0] == "advisories" && ghsaID.MatchString(p[1]) {
		return "https://api.github.com/advisories/" + p[1], p[1]
	}
	if len(p) == 5 && p[2] == "security" && p[3] == "advisories" && ghsaID.MatchString(p[4]) && repoName.MatchString(p[0]) && repoName.MatchString(p[1]) && p[0] != "." && p[0] != ".." && p[1] != "." && p[1] != ".." {
		return "https://api.github.com/repos/" + p[0] + "/" + p[1] + "/security-advisories/" + p[4], p[4]
	}
	return "", ""
}
