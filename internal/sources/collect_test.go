package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

func fixture(t *testing.T) string {
	t.Helper()
	p, e := filepath.Abs("../../testdata/synthetic")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func copyFixture(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	es, e := os.ReadDir(fixture(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range es {
		b, e := os.ReadFile(filepath.Join(fixture(t), f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(p, f.Name()), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return p
}
func write(t *testing.T, p, name, body string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(p, name+".json"), []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestFixture(t *testing.T) {
	c := Collector{Fixture: fixture(t)}
	a, e := c.Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Fetch(context.Background(), a.CVEID)
	if e != nil {
		t.Fatal(e)
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatal("fixture not deterministic")
	}
	if a.State != evidence.OK || a.KEV.Status != evidence.NotFound || a.EPSS.Status != evidence.OK || *a.EPSS.Score != 0.123 || len(a.Conflicts) == 0 || len(a.Fixed) != 1 {
		t.Fatalf("unexpected evidence: %+v", a)
	}
	for _, f := range a.Facts {
		if len(f.SourceIDs) == 0 {
			t.Fatal("unattributed fact")
		}
	}
}
func TestMalformedAndPartial(t *testing.T) {
	for _, tc := range []struct{ name, epss string }{{"invalid JSON", "{"}, {"null", "null"}, {"wrong shape", "{}"}, {"mismatch", `{"data":[{"cve":"CVE-2026-9999","epss":"0.1","date":"2026-10-24"}]}`}, {"NaN", `{"data":[{"cve":"CVE-2026-0001","epss":"NaN","date":"2026-10-24"}]}`}} {
		t.Run(tc.name, func(t *testing.T) {
			p := copyFixture(t)
			write(t, p, "epss", tc.epss)
			d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
			if e != nil || d.State != evidence.OK || d.EPSS.Status != evidence.Unknown || len(d.Warnings) == 0 {
				t.Fatalf("partial evidence lost: %+v %v", d, e)
			}
		})
	}
	p := copyFixture(t)
	if e := os.Remove(filepath.Join(p, "kev.json")); e != nil {
		t.Fatal(e)
	}
	d, _ := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
	if d.KEV.Status != evidence.Unknown {
		t.Fatal("failed KEV interpreted as absent")
	}
}
func TestPublicationStates(t *testing.T) {
	for _, state := range []string{"REJECTED", "RESERVED", "BOGUS"} {
		t.Run(state, func(t *testing.T) {
			p := copyFixture(t)
			write(t, p, "cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"`+state+`"}}`)
			d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
			if e != nil {
				t.Fatal(e)
			}
			if state == "REJECTED" && d.State != evidence.NotApplicable {
				t.Fatal(d.State)
			}
			if state != "REJECTED" && d.State != evidence.Unknown {
				t.Fatal(d.State)
			}
		})
	}
}

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		err  error
		want evidence.Status
	}{{"unknown CVE", 404, nil, evidence.NotFound}, {"rate limit", 429, nil, evidence.FetchFailed}, {"offline", 0, errors.New("secret must not escape"), evidence.FetchFailed}} {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{Client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.code, Header: http.Header{"Retry-After": []string{"99"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			d, _ := c.Fetch(ctx, "CVE-2026-0001")
			if d.Sources[0].Status != tc.want || d.KEV.Status != evidence.Unknown {
				t.Fatalf("%+v", d)
			}
			b, _ := json.Marshal(d)
			if strings.Contains(string(b), "secret") {
				t.Fatal("error leakage")
			}
		})
	}
}
func TestLimitsAndRetry(t *testing.T) {
	n := 0
	c := Collector{Client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		n++
		code := 200
		if n == 1 {
			code = 429
		}
		return &http.Response{StatusCode: code, Header: http.Header{"Retry-After": []string{"0"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}}
	r := c.get(context.Background(), "x", "https://api.first.org/data/v1/epss")
	if r.Code != 200 || n != 2 {
		t.Fatal(r, n)
	}
	c.Client.Transport = transport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxBody+1)))}, nil
	})
	c.last = nil
	if r := c.get(context.Background(), "x", "https://api.first.org/data/v1/epss"); !strings.Contains(r.Reason, "size limit") {
		t.Fatal(r.Reason)
	}
}
func TestTrustBoundary(t *testing.T) {
	for _, s := range []string{"http://api.github.com/advisories", "https://api.github.com.evil.test/", "https://127.0.0.1/", "https://user:pass@api.github.com/", "https://api.github.com:444/"} {
		if safeURL(s) {
			t.Fatal("unsafe URL", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "0.0.0.0", "100.100.100.200", "198.18.0.1", "2001:db8::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Fatal("unsafe IP", s)
		}
	}
	for _, s := range []string{"https://github.com/../../security/advisories/GHSA-w8hw-w9fx-j79w", "https://github.com.evil.test/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"} {
		if u, _ := advisoryURL(s); u != "" {
			t.Fatal(u)
		}
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/", nil)
	if NewClient().CheckRedirect(req, nil) == nil {
		t.Fatal("redirect allowed")
	}
}
func TestPHPBaseline(t *testing.T) {
	d, e := (&Collector{Fixture: "../../testdata/CVE-2026-109618"}).Fetch(context.Background(), "CVE-2026-109618")
	if e != nil {
		t.Fatal(e)
	}
	if d.State != evidence.OK || len(d.Fixed) != 4 {
		t.Fatalf("baseline versions lost: %d", len(d.Fixed))
	}
	found := false
	for _, f := range d.Facts {
		if f.Field == "advisory_description" {
			var s string
			json.Unmarshal(f.Value, &s)
			found = strings.Contains(s, "no complete FPM exploit has been demonstrated") && strings.Contains(s, "validated over HTTP against mod_php")
		}
	}
	if !found {
		t.Fatal("SAPI evidence distinction lost")
	}
}

func TestInvalidJSONCannotProduceFacts(t *testing.T) {
	p := copyFixture(t)
	write(t, p, "cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"must not be trusted"}]}}} trailing`)
	d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	if d.Sources[0].Status != evidence.FetchFailed {
		t.Fatal("invalid source accepted")
	}
	for _, f := range d.Facts {
		for _, id := range f.SourceIDs {
			if id == "S1" {
				t.Fatal("fact came from invalid JSON")
			}
		}
	}
}

func TestGoldenEvidence(t *testing.T) {
	d, e := (&Collector{Fixture: "../../testdata/CVE-2026-109618"}).Fetch(context.Background(), "CVE-2026-109618")
	if e != nil {
		t.Fatal(e)
	}
	got, e := json.MarshalIndent(d, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	got = append(got, '\n')
	want, e := os.ReadFile("../../testdata/CVE-2026-109618/evidence.golden.json")
	if e != nil {
		t.Fatal(e)
	}
	if string(got) != string(want) {
		t.Fatal("normalized baseline differs from reviewed golden JSON")
	}
	versions := map[string]bool{}
	for _, f := range d.Lookup(d.Fixed) {
		var v map[string]any
		if e := json.Unmarshal(f.Value, &v); e != nil {
			t.Fatal(e)
		}
		versions[str(v["version"])] = true
	}
	for _, v := range []string{"8.2.35", "8.3.36", "8.4.27", "8.5.12"} {
		if !versions[v] {
			t.Fatal("missing patched branch", v)
		}
	}
}

func TestReferenceIdentity(t *testing.T) {
	p := copyFixture(t)
	write(t, p, "cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Test"}],"references":[{"url":"https://bugs.php.net/bug.php?id=81234#details"},{"url":"https://bugs.php.net/bug.php?id=81235"}]}}}`)
	d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	urls := map[string]bool{}
	for _, s := range d.Sources {
		urls[s.URL] = true
	}
	for _, url := range []string{"https://bugs.php.net/bug.php?id=81234#details", "https://bugs.php.net/bug.php?id=81235"} {
		if !urls[url] {
			t.Fatal("reference lost", url)
		}
	}
}

func TestGlobalPatchedVersion(t *testing.T) {
	for _, version := range []any{"1.2.3", obj{"identifier": "1.2.3"}} {
		t.Run(fmt.Sprintf("%T", version), func(t *testing.T) {
			p := copyFixture(t)
			write(t, p, "cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Test"}],"references":[{"url":"https://github.com/advisories/GHSA-w8hw-w9fx-j79w"}]}}}`)
			raw, _ := json.Marshal(obj{"ghsa_id": "GHSA-w8hw-w9fx-j79w", "cve_id": "CVE-2026-0001", "vulnerabilities": []any{obj{"package": obj{"name": "test"}, "first_patched_version": version}}})
			write(t, p, "GHSA-w8hw-w9fx-j79w", string(raw))
			d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
			if e != nil {
				t.Fatal(e)
			}
			if len(d.Fixed) != 1 {
				t.Fatal("missing fixed version")
			}
			var value obj
			json.Unmarshal(d.Lookup(d.Fixed)[0].Value, &value)
			if str(value["version"]) != "1.2.3" || str(object(value["package"])["name"]) != "test" {
				t.Fatal(value)
			}
		})
	}
}

func TestInvalidSourceHasNoFacts(t *testing.T) {
	for _, tc := range []struct{ key, body, source string }{
		{"cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[]}}}`, "S1"},
		{"cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"BOGUS"}}`, "S1"},
		{"nvd", `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"Valid first entry"}]}},{"cve":{"id":"CVE-2026-9999"}}]}`, "S2"},
	} {
		t.Run(tc.key+tc.body, func(t *testing.T) {
			p := copyFixture(t)
			write(t, p, tc.key, tc.body)
			d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
			if e != nil {
				t.Fatal(e)
			}
			for _, s := range d.Sources {
				if s.ID == tc.source && s.Status != evidence.FetchFailed {
					t.Fatal("invalid source accepted")
				}
			}
			for _, facts := range [][]evidence.Fact{d.Facts, d.Lookup(d.CVSS), d.Lookup(d.Affected), d.Lookup(d.Fixed)} {
				for _, f := range facts {
					for _, id := range f.SourceIDs {
						if id == tc.source {
							t.Fatal("failed source produced fact", f.ID)
						}
					}
				}
			}
		})
	}
}

func TestRetryAfterBounded(t *testing.T) {
	for _, value := range []string{"31", "9999999999999", "184467440737095516160000"} {
		t.Run(value, func(t *testing.T) {
			calls := 0
			c := Collector{Client: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{value}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}}
			r := c.get(context.Background(), "x", "https://api.first.org/data/v1/epss")
			if calls != 1 || r.Reason != "retry delay exceeds budget" {
				t.Fatal(calls, r)
			}
		})
	}
}

func TestDialFallback(t *testing.T) {
	ips := []net.IPAddr{{IP: net.ParseIP("2606:4700:4700::1111")}, {IP: net.ParseIP("1.1.1.1")}}
	attempts := []string{}
	client, server := net.Pipe()
	defer server.Close()
	conn, e := dialPublic(context.Background(), "tcp", "443", ips, func(ctx context.Context, network, address string) (net.Conn, error) {
		attempts = append(attempts, address)
		if len(attempts) == 1 {
			return nil, errors.New("IPv6 unreachable")
		}
		return client, nil
	})
	if e != nil || conn != client || len(attempts) != 2 || attempts[1] != "1.1.1.1:443" {
		t.Fatal(attempts, e)
	}
	conn.Close()
	ips[1].IP = net.ParseIP("127.0.0.1")
	_, e = dialPublic(context.Background(), "tcp", "443", ips, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial attempted before all IPs validated")
		return nil, nil
	})
	if e == nil {
		t.Fatal("private address allowed")
	}
}

func TestWarningDeduplication(t *testing.T) {
	p := copyFixture(t)
	write(t, p, "cve", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"RESERVED"}}`)
	write(t, p, "nvd", `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"A"}]}},{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"B"}]}}]}`)
	d, e := (&Collector{Fixture: p}).Fetch(context.Background(), "CVE-2026-0001")
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, w := range d.Warnings {
		if seen[w] {
			t.Fatal("duplicate warning", w)
		}
		seen[w] = true
	}
}
