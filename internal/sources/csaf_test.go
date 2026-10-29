package sources

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

func TestCiscoAdvisoryID(t *testing.T) {
	for raw, want := range map[string]string{
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-afw-zqYJkjxp":           "cisco-sa-esa-afw-zqyjkjxp",
		"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2/":                     "cisco-sa-20180328-smi2",
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls1.3-dos-dlxwfwgf":    "cisco-sa-ftd-tls1.3-dos-dlxwfwgf",
		"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp":                       "cisco-sa-20170629-snmp",
		"ftp://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-x":                            "",
		"https://sec.cloudapps.cisco.com.evil.test/security/center/content/CiscoSecurityAdvisory/cisco-sa-x":                "",
		"https://user@sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-x":                     "",
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-x/extra":                    "",
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-..":                         "",
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-a%2Fb":                      "",
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/other-sa-x":                          "",
		"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-" + strings.Repeat("a", 81): "",
		"https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html":                      "",
	} {
		if got := ciscoAdvisoryID(raw); got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}

func TestParseCSAFIndex(t *testing.T) {
	paths, reason := parseCSAFIndex([]byte("2026/cisco-sa-a.json\r\n\n2025/cisco-sa-b_c.1.json\n"))
	if reason != "" || paths["cisco-sa-a.json"] != "2026/cisco-sa-a.json" || paths["cisco-sa-b_c.1.json"] != "2025/cisco-sa-b_c.1.json" || len(paths) != 2 {
		t.Fatal(paths, reason)
	}
	for name, body := range map[string]string{
		"traversal":  "2026/cisco-sa-a.json\n../../etc/passwd\n",
		"upper case": "2026/cisco-sa-A.json\n",
		"no year":    "cisco-sa-a.json\n",
		"not json":   "2026/cisco-sa-a.txt\n",
		"empty":      "\n\n",
		"duplicate":  "2026/cisco-sa-a.json\n2025/cisco-sa-a.json\n",
	} {
		if paths, reason := parseCSAFIndex([]byte(body)); paths != nil || reason == "" {
			t.Errorf("%s accepted: %v", name, paths)
		}
	}
}

// The synthetic fixture references one Cisco advisory page; its CSAF document
// is found through the index and every fact points into the retrieved body.
func TestCSAFFixture(t *testing.T) {
	dir := fixture(t)
	d, e := (&Collector{Fixture: dir}).Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	index, csaf := source(d, "csaf_index"), source(d, "csaf")
	if index.Status != evidence.OK || index.SHA256 == "" || index.URL != ciscoIndexURL {
		t.Fatalf("index not recorded: %+v", index)
	}
	if csaf.Status != evidence.OK || csaf.URL != ciscoCSAFBase+"2026/cisco-sa-synthetic-abcd.json" || csaf.PublishedAt == nil || *csaf.PublishedAt != "2026-10-20T16:00:00+00:00" {
		t.Fatalf("advisory not recorded: %+v", csaf)
	}
	for _, s := range d.Sources {
		if s.Kind == "reference" && strings.Contains(s.URL, "CiscoSecurityAdvisory") {
			t.Fatal("fetched advisory also listed as unfetched", s)
		}
	}
	pointers := map[string][]string{}
	for _, f := range d.Facts {
		if f.SourceIDs[0] == csaf.ID {
			pointers[f.Field] = append(pointers[f.Field], f.SourcePointer)
		}
	}
	for field, want := range map[string][]string{
		"advisory_state":       {"/document/tracking/status"},
		"advisory_summary":     {"/vulnerabilities/0/title"},
		"advisory_description": {"/document/notes/0/text"},
		"advisory_note":        {"/document/notes/1", "/vulnerabilities/0/notes/0"},
		"weakness":             {"/vulnerabilities/0/cwe"},
		"cvss":                 {"/vulnerabilities/0/scores/0/cvss_v3"},
		"affected":             {"/vulnerabilities/0/product_status/known_affected/0", "/vulnerabilities/0/product_status/known_affected/1", "/vulnerabilities/0/product_status/known_not_affected/0"},
		"fixed":                nil,
		"remediation":          {"/vulnerabilities/0/remediations/0"},
		"threat":               {"/vulnerabilities/0/threats/0"},
	} {
		if strings.Join(pointers[field], " ") != strings.Join(want, " ") {
			t.Errorf("%s: got %v, want %v", field, pointers[field], want)
		}
	}
	for _, f := range d.Facts {
		var s string
		if f.Field == "advisory_note" && json.Unmarshal(f.Value, &s) == nil {
			t.Fatal("note recorded without its category and title")
		}
		if strings.Contains(string(f.Value), "Fictional disclaimer") {
			t.Fatal("legal disclaimer became a fact", f.ID)
		}
	}
	var affected []obj
	for _, f := range d.Lookup(d.Affected) {
		if f.SourceIDs[0] != csaf.ID {
			continue
		}
		var v obj
		json.Unmarshal(f.Value, &v)
		affected = append(affected, v)
		if string(f.Original) != `"`+str(v["product_id"])+`"` {
			t.Fatal("product ID not kept as original", f)
		}
	}
	if len(affected) != 3 || str(affected[0]["status"]) != "known_affected" || str(affected[0]["name"]) != "1.0.1" || str(affected[2]["status"]) != "known_not_affected" || str(affected[2]["name"]) != "2.0.0" {
		t.Fatalf("product statuses lost: %v", affected)
	}
	branches, _ := json.Marshal(affected[0]["branches"])
	if string(branches) != `[{"category":"vendor","name":"Synthetic Networks"},{"category":"product_family","name":"Synthetic Gateway"},{"category":"product_version","name":"1.0"},{"category":"service_pack","name":"1.0.1"}]` {
		t.Fatal("branch path lost", string(branches))
	}
	if r := object(affected[1]["relationship"]); str(affected[1]["name"]) != "Synthetic Gateway 1.0.1 when installed on Synthetic Gateway Appliance" || str(r["category"]) != "installed_on" || str(r["relates_to_product_reference"]) != "CSAFPID-3" {
		t.Fatal("relationship product lost", affected[1])
	}
	if len(d.Fixed) != 1 || warned(d, "product tree") || warned(d, "not final") {
		t.Fatal("fixed index or warnings unexpected", d.Fixed, d.Warnings)
	}
	assertFactsFromValidSources(t, d)
	b, e := os.ReadFile(filepath.Join(dir, "cisco-sa-synthetic-abcd.json"))
	if e != nil {
		t.Fatal(e)
	}
	var body any
	json.Unmarshal(b, &body)
	for _, f := range d.Facts {
		if f.SourceIDs[0] != csaf.ID {
			continue
		}
		at, ok := resolve(body, f.SourcePointer)
		if !ok {
			t.Fatalf("%s: pointer %s does not resolve", f.ID, f.SourcePointer)
		}
		want := f.Value
		if f.Original != nil {
			want = f.Original
		}
		got, _ := json.Marshal(at)
		var expected any
		json.Unmarshal(want, &expected)
		norm, _ := json.Marshal(expected)
		if string(got) != string(norm) {
			t.Fatalf("%s: value at %s differs from recorded original", f.ID, f.SourcePointer)
		}
	}
}

// A second reference to the same advisory is kept, but not fetched twice.
func TestCSAFDuplicateReference(t *testing.T) {
	p := copyFixture(t)
	write(t, p, "cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Test"}],"references":[{"url":"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-synthetic-AbCd"},{"url":"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-synthetic-abcd"}]}}}`)
	d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	kinds := map[string]int{}
	var duplicate evidence.Source
	for _, s := range d.Sources {
		kinds[s.Kind]++
		if s.Kind == "reference" && strings.HasPrefix(s.URL, "https://tools.cisco.com/") {
			duplicate = s
		}
	}
	if kinds["csaf"] != 1 || kinds["csaf_index"] != 1 || duplicate.Status != evidence.Unknown || !strings.Contains(duplicate.Reason, "earlier reference") {
		t.Fatalf("duplicate advisory handling: %v %+v", kinds, duplicate)
	}
}

func TestContradictingProducts(t *testing.T) {
	status := obj{
		"first_affected":      []any{"A", "B"},
		"known_affected":      []any{"A", "C", "D"},
		"last_affected":       []any{"E"},
		"known_not_affected":  []any{"B", "F"},
		"fixed":               []any{"C", "G"},
		"first_fixed":         []any{"G"},
		"under_investigation": []any{"D", "F", ""},
		"recommended":         []any{"A", "B", "C", "E", "G"},
	}
	if got := strings.Join(contradictingProducts(status), ","); got != "C,D,B,F" {
		t.Fatal(got)
	}
	if got := contradictingProducts(obj{"known_affected": []any{"A"}, "fixed": []any{"B"}}); len(got) != 0 {
		t.Fatal(got)
	}
}
