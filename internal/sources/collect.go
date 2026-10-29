package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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
		if kind == "csaf" {
			published = str(object(object(m["document"])["tracking"])["initial_release_date"])
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
	v, s := c.load(ctx, &d, "cve.json", "cve_record", "https://cveawg.mitre.org/api/cve/"+id)
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
				if !hasDescription(cna["descriptions"]) {
					fail(&d, s, "published CVE lacks descriptions")
					valid = false
				}
			}
			if valid {
				d.Add("publication_state", state, s, evidence.Pointer("cveMetadata", "state"))
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
				addDescriptions(&d, cna["descriptions"], s, "containers", "cna", "descriptions")
				for i, a := range list(cna["affected"]) {
					d.Add("affected", a, s, evidence.Pointer("containers", "cna", "affected", i))
				}
				for i, a := range list(cna["affected"]) {
					addRecordVersions(&d, object(a), s, i)
				}
				for i, m := range list(cna["metrics"]) {
					d.Add("cvss", m, s, evidence.Pointer("containers", "cna", "metrics", i))
				}
				for i, p := range list(cna["problemTypes"]) {
					d.Add("weakness", p, s, evidence.Pointer("containers", "cna", "problemTypes", i))
				}
				for i, r := range list(cna["references"]) {
					addReference(&d, object(r)["url"], s, evidence.Pointer("containers", "cna", "references", i, "url"))
				}
			}
		}
	} else if d.Sources[0].Status == evidence.NotFound {
		d.State = evidence.NotFound
	}
	v, s = c.load(ctx, &d, "nvd.json", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+id)
	if v != nil {
		addNVD(&d, object(v), id, s)
	}
	// Only advisory URLs derived from recognized references are fetched: GitHub
	// advisory pages through the GitHub API, and Cisco advisory pages through
	// Cisco's CSAF distribution. Other references remain visible with a reason.
	refs := append([]evidence.Fact(nil), d.Facts...)
	seen := map[string]bool{}
	fetchedReferences := 0
	cisco := &ciscoIndex{}
	unfetched := func(raw, reason string) {
		d.Sources = append(d.Sources, evidence.Source{ID: fmt.Sprintf("S%d", len(d.Sources)+1), Kind: "reference", Title: "Unfetched reference", URL: raw, RetrievedAt: now, Status: evidence.Unknown, Reason: reason})
	}
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
		advisory := ciscoAdvisoryID(raw)
		if api == "" && advisory == "" {
			unfetched(raw, "Reference retained; unsupported adapter or unverified vendor")
			continue
		}
		if advisory != "" && seen["cisco:"+advisory] {
			unfetched(raw, "Advisory already retrieved from another reference")
			continue
		}
		if fetchedReferences >= 32 {
			unfetched(raw, "Reference fetch limit reached")
			d.Warnings = append(d.Warnings, "reference fetch limit reached")
			continue
		}
		fetchedReferences++
		if advisory != "" {
			seen["cisco:"+advisory] = true
			path, reason := cisco.lookup(ctx, c, &d, advisory)
			if path == "" {
				unfetched(raw, reason)
				continue
			}
			v, s = c.load(ctx, &d, advisory+".json", "csaf", ciscoCSAFBase+path)
			if v != nil {
				addCSAF(&d, object(v), id, advisory, s)
			}
			continue
		}
		v, s = c.load(ctx, &d, key+".json", "ghsa", api)
		if v == nil {
			continue
		}
		addAdvisory(&d, object(v), id, key, s)
	}
	v, s = c.load(ctx, &d, "kev.json", "cisa_kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	d.KEV.SourceIDs = []string{s}
	if v != nil {
		addKEV(&d, object(v), id, s)
	}
	v, s = c.load(ctx, &d, "epss.json", "first_epss", "https://api.first.org/data/v1/epss?cve="+id)
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
			if len(items) != 1 || str(r["cve"]) != id || err != nil || !(score >= 0 && score <= 1) || dateErr != nil {
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
func addDescriptions(d *evidence.Document, v any, s string, base ...any) {
	for i, item := range list(v) {
		r := object(item)
		value := str(r["value"])
		if value != "" {
			d.AddNormalized("description", obj{"lang": r["lang"], "value": value}, item, s, evidence.Pointer(append(base, i)...))
		}
	}
}
func addReference(d *evidence.Document, v any, s, pointer string) {
	if raw := cleanURL(str(v)); raw != "" {
		d.AddNormalized("reference", raw, v, s, pointer)
	}
}

func hasDescription(v any) bool {
	for _, entry := range list(v) {
		if strings.TrimSpace(str(object(entry)["value"])) != "" {
			return true
		}
	}
	return false
}

// addNVD validates the whole response before adding facts. A record that only
// echoes the ID carries no usable evidence and must not count as success.
func addNVD(d *evidence.Document, n obj, id, s string) {
	items, valid := n["vulnerabilities"].([]any)
	if !valid {
		fail(d, s, "missing NVD vulnerabilities array")
		return
	}
	total, isCount := count(n["totalResults"])
	if !isCount {
		fail(d, s, "NVD totalResults is not a non-negative integer")
		return
	}
	if total != len(items) {
		fail(d, s, "NVD totalResults does not match returned records")
		return
	}
	for _, item := range items {
		r := object(object(item)["cve"])
		if str(r["id"]) != id {
			fail(d, s, "NVD response ID mismatch")
			return
		}
		if !hasDescription(r["descriptions"]) {
			fail(d, s, "NVD record lacks descriptions")
			return
		}
	}
	if len(items) == 0 {
		d.Sources[len(d.Sources)-1].Status = evidence.NotFound
		d.Warnings = append(d.Warnings, s+": no NVD record")
		return
	}
	for i, item := range items {
		r := object(object(item)["cve"])
		at := func(parts ...any) string {
			return evidence.Pointer(append([]any{"vulnerabilities", i, "cve"}, parts...)...)
		}
		if d.State == evidence.NotFound || d.State == evidence.Unknown {
			d.Warnings = append(d.Warnings, "NVD has a record; official CVE publication state remains unconfirmed")
		}
		if status := str(r["vulnStatus"]); status != "" {
			d.Add("nvd_status", status, s, at("vulnStatus"))
		}
		addDescriptions(d, r["descriptions"], s, "vulnerabilities", i, "cve", "descriptions")
		if m := object(r["metrics"]); len(m) > 0 {
			d.Add("cvss", m, s, at("metrics"))
		}
		if a := list(r["configurations"]); len(a) > 0 {
			d.Add("affected", a, s, at("configurations"))
		}
		for j, w := range list(r["weaknesses"]) {
			d.Add("weakness", w, s, at("weaknesses", j))
		}
		for j, ref := range list(r["references"]) {
			addReference(d, object(ref)["url"], s, at("references", j, "url"))
		}
	}
}

// addAdvisory keeps the GHSA fields needed to judge the advisory itself:
// identity, withdrawal, severity, weaknesses and per-package versions.
func addAdvisory(d *evidence.Document, a obj, id, ghsa, s string) {
	if str(a["cve_id"]) != id {
		fail(d, s, "advisory CVE mismatch")
		return
	}
	if got, isString := a["ghsa_id"].(string); !isString || got == "" {
		fail(d, s, "advisory lacks GHSA ID")
		return
	} else if got != ghsa {
		fail(d, s, "advisory GHSA ID mismatch")
		return
	}
	if state := str(a["state"]); state != "" {
		d.Add("advisory_state", state, s, evidence.Pointer("state"))
		if state != "published" {
			d.Warnings = append(d.Warnings, s+": advisory state is "+state+", not published")
		}
	}
	if withdrawn := str(a["withdrawn_at"]); withdrawn != "" {
		d.Add("advisory_withdrawn", withdrawn, s, evidence.Pointer("withdrawn_at"))
		d.Warnings = append(d.Warnings, s+": advisory withdrawn at "+withdrawn+"; do not use as current evidence")
	}
	if summary := str(a["summary"]); summary != "" {
		d.Add("advisory_summary", summary, s, evidence.Pointer("summary"))
	}
	if body := str(a["description"]); body != "" {
		d.Add("advisory_description", body, s, evidence.Pointer("description"))
	}
	if severity := str(a["severity"]); severity != "" {
		d.Add("advisory_severity", severity, s, evidence.Pointer("severity"))
	}
	scored := false
	severities := object(a["cvss_severities"])
	for _, version := range []string{"cvss_v3", "cvss_v4"} {
		if m := object(severities[version]); m["vector_string"] != nil || m["score"] != nil {
			d.Add("cvss", m, s, evidence.Pointer("cvss_severities", version))
			scored = true
		}
	}
	if m := object(a["cvss"]); !scored && (m["vector_string"] != nil || m["score"] != nil) {
		d.Add("cvss", m, s, evidence.Pointer("cvss"))
	}
	for i, w := range list(a["cwes"]) {
		d.Add("weakness", w, s, evidence.Pointer("cwes", i))
	}
	for i, v := range list(a["vulnerabilities"]) {
		at := func(parts ...any) string { return evidence.Pointer(append([]any{"vulnerabilities", i}, parts...)...) }
		pkg := object(v)["package"]
		d.Add("affected", v, s, at())
		patched := str(object(v)["patched_versions"])
		if patched != "" {
			d.AddNormalized("fixed", obj{"package": pkg, "version": patched}, patched, s, at("patched_versions"))
		}
		first, pointer := object(v)["first_patched_version"], at("first_patched_version")
		fixed := str(first)
		if fixed == "" {
			fixed, pointer = str(object(first)["identifier"]), at("first_patched_version", "identifier")
		}
		if fixed != "" && fixed != patched {
			d.AddNormalized("fixed", obj{"package": pkg, "version": fixed}, fixed, s, pointer)
		}
	}
}

// addRecordVersions derives, for one affected product of the CVE record, the
// fixed versions the record states and the bounds it leaves undeclared.
//
// A fixed fact comes from a version listed as unaffected, a change to
// unaffected inside a range, and the upper bound of an affected range when the
// product's defaultStatus is unaffected (the record then declares that bound
// unaffected). An affected_bound fact comes from the lessThan of an affected
// range that the record does not declare unaffected, so that the Skill can
// present it as an estimate rather than a fix. Wildcards, "All" and
// lessThanOrEqual (inclusive) produce neither, and nothing is derived for a
// product the record does not mark affected anywhere.
func addRecordVersions(d *evidence.Document, a obj, s string, i int) {
	at := func(parts ...any) string {
		return evidence.Pointer(append([]any{"containers", "cna", "affected", i}, parts...)...)
	}
	versions := list(a["versions"])
	affected := str(a["defaultStatus"]) == "affected"
	for _, v := range versions {
		affected = affected || str(object(v)["status"]) == "affected"
	}
	if !affected {
		return
	}
	type derived struct{ field, version, branch, pointer string }
	var facts []derived
	fixed := map[string]bool{}
	add := func(field, version, branch, pointer string) {
		if version == "" || strings.Contains(version, "*") || strings.EqualFold(version, "all") {
			return
		}
		for _, f := range facts {
			if f.field == field && f.version == version && f.branch == branch {
				return
			}
		}
		facts = append(facts, derived{field, version, branch, pointer})
		if field == "fixed" {
			fixed[version] = true
		}
	}
	unaffectedDefault := str(a["defaultStatus"]) == "unaffected"
	for j, v := range versions {
		entry := object(v)
		single := entry["lessThan"] == nil && entry["lessThanOrEqual"] == nil && len(list(entry["changes"])) == 0
		switch str(entry["status"]) {
		case "unaffected":
			if single {
				add("fixed", str(entry["version"]), "", at("versions", j, "version"))
			}
		case "affected":
			if entry["lessThan"] != nil {
				field := "affected_bound"
				if unaffectedDefault {
					field = "fixed"
				}
				add(field, str(entry["lessThan"]), str(entry["version"]), at("versions", j, "lessThan"))
			}
		}
		for k, c := range list(entry["changes"]) {
			if str(object(c)["status"]) == "unaffected" {
				add("fixed", str(object(c)["at"]), str(entry["version"]), at("versions", j, "changes", k, "at"))
			}
		}
	}
	for _, f := range facts {
		if f.field == "affected_bound" && fixed[f.version] {
			continue
		}
		value := obj{"version": f.version}
		for _, key := range []string{"vendor", "product", "packageName"} {
			if text := str(a[key]); text != "" {
				value[key] = text
			}
		}
		if f.branch != "" {
			value["branch"] = f.branch
		}
		d.AddNormalized(f.field, value, f.version, s, f.pointer)
	}
}

// count accepts only a JSON number that is a non-negative integer, so that a
// fractional or negative declared size cannot be truncated into a match.
func count(v any) (int, bool) {
	f, isNumber := v.(float64)
	if !isNumber || f < 0 || f != math.Trunc(f) || f > math.MaxInt32 {
		return 0, false
	}
	return int(f), true
}

// addKEV judges absence only from a catalog whose declared count matches its
// entries; a truncated or malformed catalog cannot show that a CVE is absent.
func addKEV(d *evidence.Document, k obj, id, s string) {
	items, valid := k["vulnerabilities"].([]any)
	if !valid || str(k["catalogVersion"]) == "" {
		fail(d, s, "invalid KEV catalog")
		return
	}
	declared, isCount := count(k["count"])
	if !isCount {
		fail(d, s, "KEV catalog count is not a non-negative integer")
		return
	}
	if declared != len(items) {
		fail(d, s, fmt.Sprintf("KEV catalog count %d does not match %d entries", declared, len(items)))
		return
	}
	matches := []int{}
	for i, item := range items {
		r, isObject := item.(map[string]any)
		if !isObject || strings.TrimSpace(str(r["cveID"])) == "" {
			fail(d, s, fmt.Sprintf("KEV catalog entry %d lacks cveID", i))
			return
		}
		if str(r["cveID"]) == id {
			matches = append(matches, i)
		}
	}
	d.KEV.Status = evidence.NotFound
	if len(matches) > 1 {
		d.Warnings = append(d.Warnings, s+": CVE listed more than once in KEV catalog")
	}
	for _, i := range matches {
		d.KEV.Status = evidence.OK
		d.Add("known_exploitation", items[i], s, evidence.Pointer("vulnerabilities", i))
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
