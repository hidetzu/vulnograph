package sources

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

// Cisco publishes every security advisory as a CSAF 2.0 document under a
// directory-based distribution whose index.txt lists one path per advisory,
// year/<advisory-id>.json with the ID in lower case. The advisory page the CVE
// record references names only the ID, so the index is read to find the path.
const ciscoCSAFBase = "https://www.cisco.com/.well-known/csaf/"
const ciscoIndexURL = ciscoCSAFBase + "index.txt"

var ciscoID = regexp.MustCompile(`^cisco-sa-[A-Za-z0-9_.-]{1,80}$`)
var csafIndexEntry = regexp.MustCompile(`^[0-9]{4}/[a-z0-9_.-]+\.json$`)

// ciscoAdvisoryID returns the lower-cased advisory ID named by a Cisco Security
// Advisory page URL, or "" for any other URL. The page is never fetched, only
// its ID is looked up, so the http form of old references is accepted too.
func ciscoAdvisoryID(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || (u.Host != "sec.cloudapps.cisco.com" && u.Host != "tools.cisco.com") {
		return ""
	}
	p := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(p) != 5 || p[0] != "security" || p[1] != "center" || p[2] != "content" || p[3] != "CiscoSecurityAdvisory" || !ciscoID.MatchString(p[4]) || strings.Contains(p[4], "..") {
		return ""
	}
	return strings.ToLower(p[4])
}

// ciscoIndex retrieves the distribution index at most once per run.
type ciscoIndex struct {
	loaded bool
	paths  map[string]string
	reason string
}

// lookup returns the index path of an advisory, or the reason it has none.
func (x *ciscoIndex) lookup(ctx context.Context, c *Collector, d *evidence.Document, advisory string) (string, string) {
	if !x.loaded {
		x.loaded = true
		x.paths, x.reason = c.loadCiscoIndex(ctx, d)
	}
	if x.paths == nil {
		return "", x.reason
	}
	path := x.paths[advisory+".json"]
	if path == "" {
		return "", "Advisory not listed in Cisco CSAF index"
	}
	return path, ""
}

// loadCiscoIndex records the index as a source of its own, so that the path
// each CSAF document was read from can be traced to a retrieved body.
func (c *Collector) loadCiscoIndex(ctx context.Context, d *evidence.Document) (map[string]string, string) {
	r, s := c.retrieve(ctx, d, "cisco-csaf-index.txt", "csaf_index", ciscoIndexURL)
	var paths map[string]string
	if s.Status == evidence.NotFound {
		s.Status = evidence.FetchFailed
	}
	if s.Status == evidence.OK {
		if paths, s.Reason = parseCSAFIndex(r.Body); paths == nil {
			s.Status = evidence.FetchFailed
			s.SHA256 = ""
		}
	}
	record(d, s)
	if s.Status != evidence.OK {
		return nil, "Cisco CSAF index unavailable"
	}
	return paths, ""
}

// parseCSAFIndex accepts only an index whose every entry is a year directory
// and a lower-case file name, so that no entry can name a path outside the
// distribution; a file listed under two years is ambiguous and rejected.
func parseCSAFIndex(b []byte) (map[string]string, string) {
	paths := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !csafIndexEntry.MatchString(line) {
			return nil, "invalid CSAF index entry"
		}
		name := line[strings.LastIndex(line, "/")+1:]
		if prior, listed := paths[name]; listed && prior != line {
			return nil, "CSAF index lists " + name + " more than once"
		}
		paths[name] = line
	}
	if len(paths) == 0 {
		return nil, "empty CSAF index"
	}
	return paths, ""
}

// csafStatuses lists every CSAF product status with the group CSAF assigns it
// to. A product may belong to one group only; recommended belongs to none and
// is never a statement that the release contains the fix. The fixed group is
// recorded as fixed facts, every other status as affected facts.
var csafStatuses = []struct{ status, group string }{
	{"known_affected", "affected"}, {"first_affected", "affected"}, {"last_affected", "affected"},
	{"known_not_affected", "not_affected"},
	{"under_investigation", "under_investigation"},
	{"recommended", ""},
	{"fixed", "fixed"}, {"first_fixed", "fixed"},
}

// addCSAF validates a CSAF 2.0 advisory before taking facts from it: the
// document must carry the tracking ID the reference named and list the CVE.
// The field layout read here is the 2.0 one (cwe, scores), so other versions
// are rejected rather than read with their weaknesses and scores missing.
// Only the vulnerability entries for this CVE are read, since one advisory
// may cover several CVEs with different product statuses.
func addCSAF(d *evidence.Document, a obj, id, advisory, s string) {
	doc := object(a["document"])
	if str(doc["csaf_version"]) != "2.0" {
		fail(d, s, "unsupported CSAF version")
		return
	}
	tracking := object(doc["tracking"])
	got, isString := tracking["id"].(string)
	if !isString || got == "" {
		fail(d, s, "CSAF document lacks tracking ID")
		return
	}
	if !strings.EqualFold(got, advisory) {
		fail(d, s, "CSAF tracking ID mismatch")
		return
	}
	vulnerabilities := list(a["vulnerabilities"])
	matches := []int{}
	for i, v := range vulnerabilities {
		if str(object(v)["cve"]) == id {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		fail(d, s, "CSAF document does not list the CVE")
		return
	}
	products := csafProducts(object(a["product_tree"]))
	if status := str(tracking["status"]); status == "" {
		d.Warnings = append(d.Warnings, s+": CSAF document has no tracking status; treat as unpublished")
	} else {
		d.Add("advisory_state", status, s, evidence.Pointer("document", "tracking", "status"))
		if status != "final" {
			d.Warnings = append(d.Warnings, s+": advisory status is "+status+", not final")
		}
	}
	if text := str(object(doc["aggregate_severity"])["text"]); text != "" {
		d.Add("advisory_severity", text, s, evidence.Pointer("document", "aggregate_severity", "text"))
	}
	addCSAFNotes(d, doc["notes"], s, "document", "notes")
	undefined := map[string]bool{}
	contradicted := map[string]bool{}
	for _, i := range matches {
		v := object(vulnerabilities[i])
		at := func(parts ...any) string { return evidence.Pointer(append([]any{"vulnerabilities", i}, parts...)...) }
		title, pointer := str(v["title"]), at("title")
		if title == "" {
			title, pointer = str(doc["title"]), evidence.Pointer("document", "title")
		}
		if title != "" {
			d.Add("advisory_summary", title, s, pointer)
		}
		addCSAFNotes(d, v["notes"], s, "vulnerabilities", i, "notes")
		if w := object(v["cwe"]); len(w) > 0 {
			d.Add("weakness", w, s, at("cwe"))
		}
		for k, score := range list(v["scores"]) {
			for _, version := range []string{"cvss_v2", "cvss_v3", "cvss_v4"} {
				if m := object(object(score)[version]); len(m) > 0 {
					d.Add("cvss", m, s, at("scores", k, version))
				}
			}
		}
		productStatus := object(v["product_status"])
		for _, productID := range contradictingProducts(productStatus) {
			if !contradicted[productID] {
				contradicted[productID] = true
				d.Warnings = append(d.Warnings, s+": CSAF product ID "+productID+" has contradicting statuses")
			}
		}
		for _, entry := range csafStatuses {
			status, field := entry.status, "affected"
			if entry.group == "fixed" {
				field = "fixed"
			}
			for m, pid := range list(productStatus[status]) {
				productID := str(pid)
				if productID == "" {
					continue
				}
				value := obj{"status": status, "product_id": productID}
				if product, defined := products[productID]; defined {
					for key, item := range product {
						value[key] = item
					}
				} else if !undefined[productID] {
					undefined[productID] = true
					d.Warnings = append(d.Warnings, s+": CSAF product ID "+productID+" is not defined in the product tree")
				}
				d.AddNormalized(field, value, pid, s, at("product_status", status, m))
			}
		}
		for k, r := range list(v["remediations"]) {
			d.Add("remediation", r, s, at("remediations", k))
		}
		for k, threat := range list(v["threats"]) {
			d.Add("threat", threat, s, at("threats", k))
		}
	}
}

// contradictingProducts returns, in order of first appearance, the product IDs
// that a product_status lists in more than one of the CSAF status groups
// (affected, not affected, fixed, under investigation). CSAF forbids this;
// vulnograph keeps every statement and warns instead of choosing one.
func contradictingProducts(productStatus obj) []string {
	seen := map[string]string{}
	var order, contradicting []string
	for _, entry := range csafStatuses {
		if entry.group == "" {
			continue
		}
		for _, pid := range list(productStatus[entry.status]) {
			productID := str(pid)
			if productID == "" {
				continue
			}
			prior, listed := seen[productID]
			if !listed {
				seen[productID] = entry.group
				order = append(order, productID)
			} else if prior != entry.group && prior != "contradicting" {
				seen[productID] = "contradicting"
			}
		}
	}
	for _, productID := range order {
		if seen[productID] == "contradicting" {
			contradicting = append(contradicting, productID)
		}
	}
	return contradicting
}

// addCSAFNotes records summary and description notes as advisory_description
// and every other note, except the legal disclaimer, as advisory_note with its
// category and title, since vendors put fixed releases and workarounds there.
func addCSAFNotes(d *evidence.Document, v any, s string, base ...any) {
	for j, n := range list(v) {
		note := object(n)
		if str(note["text"]) == "" {
			continue
		}
		switch str(note["category"]) {
		case "summary", "description":
			d.Add("advisory_description", note["text"], s, evidence.Pointer(append(base, j, "text")...))
		case "legal_disclaimer":
		default:
			d.Add("advisory_note", n, s, evidence.Pointer(append(base, j)...))
		}
	}
}

// csafProducts maps every product ID in a product tree to its name and the
// branch path that leads to it (vendor, product family, version and so on),
// so that a status entry can be read without the tree. Products defined by a
// relationship keep the relationship so the composition stays visible.
func csafProducts(tree obj) map[string]obj {
	products := map[string]obj{}
	var walk func(items []any, path []any)
	walk = func(items []any, path []any) {
		for _, item := range items {
			b := object(item)
			current := append(append([]any{}, path...), obj{"category": str(b["category"]), "name": str(b["name"])})
			if p := object(b["product"]); str(p["product_id"]) != "" {
				products[str(p["product_id"])] = obj{"name": str(p["name"]), "branches": current}
			}
			walk(list(b["branches"]), current)
		}
	}
	walk(list(tree["branches"]), nil)
	for _, item := range list(tree["full_product_names"]) {
		p := object(item)
		if id := str(p["product_id"]); id != "" {
			if _, defined := products[id]; !defined {
				products[id] = obj{"name": str(p["name"])}
			}
		}
	}
	for _, item := range list(tree["relationships"]) {
		r := object(item)
		p := object(r["full_product_name"])
		if id := str(p["product_id"]); id != "" {
			if _, defined := products[id]; !defined {
				products[id] = obj{"name": str(p["name"]), "relationship": obj{"category": str(r["category"]), "product_reference": str(r["product_reference"]), "relates_to_product_reference": str(r["relates_to_product_reference"])}}
			}
		}
	}
	return products
}
