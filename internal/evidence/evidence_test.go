package evidence

import (
	"testing"
	"time"
)

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

func TestDescriptionLanguage(t *testing.T) {
	d := New("CVE-2026-0001", time.Time{})
	d.Add("description", map[string]string{"lang": "en", "value": "Original"}, "S1", "/descriptions/0")
	d.Add("description", map[string]string{"lang": "es", "value": "Translation"}, "S2", "/descriptions/0")
	d.Add("description", map[string]string{"lang": "en", "value": "Original"}, "S2", "/descriptions/0")
	if len(d.Conflicts) != 0 {
		t.Fatal("translation or matching text flagged")
	}
	d.Add("description", map[string]string{"lang": "EN", "value": "Different"}, "S2", "/descriptions/0")
	if len(d.Conflicts) != 1 {
		t.Fatal("same-language difference lost")
	}
}
