// Package examples checks that sample reports stay traceable to their evidence.
package examples

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hidetzu/vulnograph/internal/evidence"
)

var (
	label     = regexp.MustCompile(`\["([^"]*)"\]`)
	citation  = regexp.MustCompile(`\bF([0-9]+)/S([0-9]+)\b`)
	factID    = regexp.MustCompile(`\bF[0-9]+\b`)
	node      = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9_]*)\["([^"]*)"\]`)
	edge      = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_]*)(?:\["[^"]*"\])?\s*(-->|-\.->)(?:\|[^|]*\|)?\s*([A-Za-z][A-Za-z0-9_]*)`)
	forbidden = []string{"click", "href", "http", "%%{", "<", ">", "`", "[", "]", "\""}
)

func TestExamples(t *testing.T) {
	dirs, e := filepath.Glob("CVE-*")
	if e != nil || len(dirs) == 0 {
		t.Fatal("no examples", e)
	}
	for _, dir := range dirs {
		t.Run(dir, func(t *testing.T) {
			var d evidence.Document
			b, e := os.ReadFile(filepath.Join(dir, "evidence.json"))
			if e != nil || json.Unmarshal(b, &d) != nil {
				t.Fatal("evidence unreadable", e)
			}
			sources := map[string][]string{}
			for _, f := range d.Facts {
				sources[f.ID] = f.SourceIDs
			}
			report := read(t, dir, "report.md")
			for name, layout := range map[string]string{"overview.mmd": "flowchart LR", "diagram.mmd": "flowchart TD"} {
				diagram := read(t, dir, name)
				if !strings.HasPrefix(diagram, layout+"\n") {
					t.Fatalf("%s must start with %q", name, layout)
				}
				if !strings.Contains(report, "```mermaid\n"+diagram+"```") {
					t.Fatalf("report.md does not embed %s verbatim", name)
				}
				checkDiagram(t, name, diagram, sources)
				checkPaths(t, name, parseGraph(diagram), disjointImpacts[dir])
			}
			overview := read(t, dir, "overview.mmd")
			last := -1
			for _, part := range []string{`["攻撃の入口"]`, `["脆弱性の原因"]`, `["被害"]`} {
				at := strings.Index(overview, part)
				if at <= last {
					t.Fatalf("overview lacks subgraph %s in entry, cause, harm order", part)
				}
				last = at
			}
			for _, id := range factID.FindAllString(report, -1) {
				if sources[id] == nil {
					t.Fatalf("report cites missing fact %s", id)
				}
			}
		})
	}
}

// disjointImpacts marks examples whose proven and unproven impacts arise on
// different paths, so no node may lead to both.
var disjointImpacts = map[string]bool{
	// GHSA: FPM exits the child when request startup fails; the FPM concern
	// applies only to OOM after normal startup, not to the mod_php path.
	"CVE-2026-109618": true,
}

type graph struct {
	labels map[string]string
	edges  map[string][]string
	dashed map[[2]string]bool
}

func parseGraph(diagram string) graph {
	g := graph{labels: map[string]string{}, edges: map[string][]string{}, dashed: map[[2]string]bool{}}
	for _, line := range strings.Split(diagram, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "subgraph ") {
			continue
		}
		for _, m := range node.FindAllStringSubmatch(line, -1) {
			g.labels[m[1]] = m[2]
		}
		if m := edge.FindStringSubmatch(line); m != nil {
			g.edges[m[1]] = append(g.edges[m[1]], m[3])
			g.dashed[[2]string{m[1], m[3]}] = m[2] == "-.->"
		}
	}
	return g
}

func proven(label string) bool {
	return strings.Contains(label, "実証") && !strings.Contains(label, "未実証")
}

// Unproven impacts are reached only by dashed edges. With disjoint, a node
// that leads to a proven impact must not also lead to an unproven one.
func checkPaths(t *testing.T, name string, g graph, disjoint bool) {
	t.Helper()
	for pair, dashed := range g.dashed {
		if strings.Contains(g.labels[pair[1]], "未実証") && !dashed {
			t.Fatalf("%s: unproven node %s is reached by a solid edge from %s", name, pair[1], pair[0])
		}
	}
	if !disjoint {
		return
	}
	for from := range g.labels {
		seen := map[string]bool{}
		queue := []string{from}
		var confirmed, unproven string
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			if label := g.labels[id]; proven(label) {
				confirmed = label
			} else if strings.Contains(label, "未実証") {
				unproven = label
			}
			for _, next := range g.edges[id] {
				if !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
		if confirmed != "" && unproven != "" {
			t.Fatalf("%s: %q leads to both %q and %q", name, g.labels[from], confirmed, unproven)
		}
	}
}

// Every node either cites a fact with its own source or says it is unknown,
// so diagrams cannot add attack paths that the evidence does not state.
func checkDiagram(t *testing.T, name, diagram string, sources map[string][]string) {
	t.Helper()
	for _, line := range strings.Split(diagram, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "subgraph ") {
			continue
		}
		for _, m := range label.FindAllStringSubmatch(line, -1) {
			text := m[1]
			for _, token := range forbidden {
				if strings.Contains(text, token) {
					t.Fatalf("%s: unsafe label %q", name, text)
				}
			}
			cites := citation.FindAllStringSubmatch(text, -1)
			if len(cites) == 0 && !strings.Contains(text, "不明") {
				t.Fatalf("%s: node %q has no fact citation and is not marked unknown", name, text)
			}
			for _, c := range cites {
				ids := sources["F"+c[1]]
				if len(ids) == 0 || ids[0] != "S"+c[2] {
					t.Fatalf("%s: F%s is not from S%s", name, c[1], c[2])
				}
			}
		}
	}
	lower := strings.ToLower(diagram)
	for _, token := range []string{"click ", "href", "http://", "https://", "%%{"} {
		if strings.Contains(lower, token) {
			t.Fatalf("%s contains %q", name, token)
		}
	}
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(dir, name))
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
