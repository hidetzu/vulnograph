package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hidetzu/vulnograph/internal/buildinfo"
	"github.com/hidetzu/vulnograph/internal/evidence"
	"github.com/hidetzu/vulnograph/internal/sources"
)

func run(ctx context.Context, args []string, out, errout io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(out, "vulnograph "+buildinfo.Version)
		return 0
	}
	if len(args) < 2 || args[0] != "fetch" {
		fmt.Fprintln(errout, "usage: vulnograph fetch CVE-YYYY-NNNN [--output path] [--format json] [--fixture directory]")
		return 2
	}
	id, e := evidence.CVE(args[1])
	if e != nil {
		fmt.Fprintln(errout, e)
		return 2
	}
	flags := flag.NewFlagSet("fetch", flag.ContinueOnError)
	flags.SetOutput(errout)
	output := flags.String("output", "", "output JSON path (default stdout)")
	format := flags.String("format", "json", "output format")
	fixture := flags.String("fixture", "", "offline fixture directory")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 || *format != "json" {
		fmt.Fprintln(errout, "only JSON format and documented flags are supported")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	c := sources.Collector{Fixture: *fixture, NVDKey: os.Getenv("NVD_API_KEY"), GitHubToken: os.Getenv("GITHUB_TOKEN")}
	d, e := c.Fetch(ctx, id)
	if e != nil {
		fmt.Fprintln(errout, e)
		return 1
	}
	b, e := json.MarshalIndent(d, "", "  ")
	if e != nil {
		fmt.Fprintln(errout, "JSON encoding failed")
		return 1
	}
	b = append(b, '\n')
	if *output != "" {
		dir := filepath.Dir(*output)
		if os.MkdirAll(dir, 0755) != nil {
			fmt.Fprintln(errout, "cannot create output directory")
			return 1
		}
		f, e := os.CreateTemp(dir, ".evidence-*.json")
		if e != nil {
			fmt.Fprintln(errout, "cannot create output file")
			return 1
		}
		name := f.Name()
		defer os.Remove(name)
		mode := os.FileMode(0644)
		if info, err := os.Stat(*output); err == nil {
			mode = info.Mode().Perm()
		} else if !os.IsNotExist(err) {
			f.Close()
			fmt.Fprintln(errout, "cannot inspect output file")
			return 1
		}
		if err := f.Chmod(mode); err != nil {
			f.Close()
			fmt.Fprintln(errout, "cannot set output permissions")
			return 1
		}
		_, e = f.Write(b)
		closeErr := f.Close()
		if e != nil || closeErr != nil || os.Rename(name, *output) != nil {
			fmt.Fprintln(errout, "cannot write output file")
			return 1
		}
	} else if _, e = out.Write(b); e != nil {
		fmt.Fprintln(errout, "output write failed")
		return 1
	}
	usable := false
	for _, s := range d.Sources {
		if (s.Kind == "cve_record" || s.Kind == "nvd") && s.Status == evidence.OK {
			usable = true
		}
	}
	if !usable {
		fmt.Fprintln(errout, "no usable CVE/NVD record; see JSON source statuses")
		return 1
	}
	if d.State == evidence.NotApplicable {
		fmt.Fprintln(errout, "CVE is rejected; see publication_state")
		return 1
	}
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
