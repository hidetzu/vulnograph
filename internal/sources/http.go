package sources

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hidetzu/vulnograph/internal/buildinfo"
)

const maxBody = 16 << 20

var hosts = map[string]bool{"cveawg.mitre.org": true, "services.nvd.nist.gov": true, "api.github.com": true, "www.cisa.gov": true, "api.first.org": true, "www.php.net": true}

func safeURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.User == nil && (u.Port() == "" || u.Port() == "443") && hosts[u.Hostname()]
}

// Block special-use ranges in addition to Go's private/local classifications.
var nonPublicRanges = func() []*net.IPNet {
	ranges := []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"}
	blocks := make([]*net.IPNet, 0, len(ranges))
	for _, cidr := range ranges {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		blocks = append(blocks, block)
	}
	return blocks
}()

func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, block := range nonPublicRanges {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

func NewClient() *http.Client {
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, fmt.Errorf("DNS lookup failed")
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses")
		}
		return dialPublic(ctx, network, port, ips, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return fmt.Errorf("redirect blocked") }}
}

// Validate every answer before connecting and pin each attempt to that IP.
// A per-address budget leaves time for fallback within the HTTP timeout.
func dialPublic(ctx context.Context, network, port string, ips []net.IPAddr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	for _, ip := range ips {
		if !publicIP(ip.IP) {
			return nil, fmt.Errorf("non-public address blocked")
		}
	}
	for _, ip := range ips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := dial(attempt, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("all validated addresses failed")
}

type response struct {
	Body   []byte
	Code   int
	Reason string
}
type Collector struct {
	Client      *http.Client
	Fixture     string
	Now         func() time.Time
	NVDKey      string
	GitHubToken string
	last        map[string]time.Time
}

func (c *Collector) get(ctx context.Context, key, raw string) response {
	if !safeURL(raw) {
		return response{Reason: "URL not in supported HTTPS source allowlist"}
	}
	if c.Fixture != "" {
		b, e := os.ReadFile(filepath.Join(c.Fixture, key+".json"))
		if e != nil {
			return response{Reason: "fixture unavailable"}
		}
		if len(b) > maxBody {
			return response{Reason: "response exceeds size limit"}
		}
		return response{Body: b, Code: 200}
	}
	u, _ := url.Parse(raw)
	for attempt := 0; attempt < 3; attempt++ {
		if c.last == nil {
			c.last = map[string]time.Time{}
		}
		interval := time.Second
		if u.Hostname() == "services.nvd.nist.gov" {
			interval = 6 * time.Second
			if c.NVDKey != "" {
				interval = 600 * time.Millisecond
			}
		}
		if delay := time.Until(c.last[u.Hostname()].Add(interval)); delay > 0 {
			if !pause(ctx, delay) {
				return response{Reason: "request canceled"}
			}
		}
		c.last[u.Hostname()] = time.Now()
		req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if e != nil {
			return response{Reason: "invalid request"}
		}
		req.Header.Set("User-Agent", "vulnograph/"+buildinfo.Version)
		req.Header.Set("Accept", "application/json")
		if u.Hostname() == "services.nvd.nist.gov" && c.NVDKey != "" {
			req.Header.Set("apiKey", c.NVDKey)
		}
		if u.Hostname() == "api.github.com" && c.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.GitHubToken)
		}
		res, e := c.Client.Do(req)
		if e != nil {
			if attempt < 2 && ctx.Err() == nil {
				if !pause(ctx, time.Duration(attempt+1)*time.Second) {
					break
				}
				continue
			}
			return response{Reason: "network request failed"}
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
		res.Body.Close()
		if e != nil {
			return response{Reason: "response read failed"}
		}
		if len(b) > maxBody {
			return response{Reason: "response exceeds size limit"}
		}
		if (res.StatusCode == 429 || res.StatusCode >= 500) && attempt < 2 {
			delay := time.Duration(attempt+1) * time.Second
			if s := res.Header.Get("Retry-After"); s != "" {
				if n, e := strconv.ParseUint(s, 10, 64); e == nil {
					if n > 30 {
						return response{Code: res.StatusCode, Reason: "retry delay exceeds budget"}
					}
					delay = time.Duration(n) * time.Second
				} else if strings.Trim(s, "0123456789") == "" {
					return response{Code: res.StatusCode, Reason: "retry delay exceeds budget"}
				} else if t, e := http.ParseTime(s); e == nil {
					delay = time.Until(t)
				}
			}
			if delay > 30*time.Second {
				return response{Code: res.StatusCode, Reason: "retry delay exceeds budget"}
			}
			if !pause(ctx, delay) {
				break
			}
			continue
		}
		if res.StatusCode == 403 && res.Header.Get("X-RateLimit-Remaining") == "0" {
			return response{Code: 403, Reason: "API rate limit exhausted (HTTP 403)"}
		}
		return response{Body: b, Code: res.StatusCode}
	}
	return response{Reason: "request canceled"}
}
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func cleanURL(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return ""
	}
	return strings.TrimSpace(u.String())
}
