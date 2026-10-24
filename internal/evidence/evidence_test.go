package evidence

import "testing"

func TestCVE(t *testing.T) {
	for _, s := range []string{"CVE-2026-109618", " cve-2024-1234 "} {
		if _, e := CVE(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"CVE-2026-123", "CVE-26-1234", "CVE-2026-1234/../../etc", "CVE-2026-１２３４", "CVE-2026-1234\nX"} {
		if _, e := CVE(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
