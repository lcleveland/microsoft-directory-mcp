// Package config parses flags and environment into a Config.
//
// Secrets (the AD bind password, the Entra certificate key, the HTTP bearer)
// are only ever read from files. There is deliberately no flag or environment
// variable that takes a secret's value: argv is readable from
// /proc/<pid>/cmdline and the environment from /proc/<pid>/environ.
package config

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// AD is the forest side. It is on when --ad-forest is set.
type AD struct {
	Forest             string
	BindUser           string // UPN
	BindPassword       string
	TLS                string // ldaps or starttls
	CAFile             string // added to the system roots
	InsecureSkipVerify bool
	Site               string
	DCs                []string // static domain controller list; empty means DNS SRV
	ProtectedGroups    []string // groups whose members, direct or nested, are protected targets
}

// Entra is the tenant side. It is on when --entra-tenant set.
type Entra struct {
	Tenant   string
	ClientID string
	CertPEM  []byte // private key and certificate
	Cloud    string
	LoginURL string // no trailing slash
	GraphURL string
	// PasswordWriteback is operator-declared (on, off or unknown): app-only
	// Graph cannot detect it. See docs/research/password-writeback-signal.md.
	PasswordWriteback string
}

// Groups are the tool groups, in roster order. core is always on.
var Groups = []string{"core", "identity", "security", "policy", "devices", "infra"}

// Capabilities are the write classes the operator can enable, all off by
// default. See docs/adr/0001-write-capability-map.md.
var Capabilities = []string{
	"ad-account-state", "ad-passwords", "ad-group-membership", "ad-objects", "ad-delete", "ad-gpo-links", "ad-password-policy",
	"entra-account-state", "entra-credentials", "entra-group-membership", "entra-objects", "entra-delete", "entra-licenses",
	"entra-devices", "entra-risk", "intune-device-actions", "intune-retire-wipe",
}

type Config struct {
	AD    *AD    // nil when the side is off
	Entra *Entra // nil when the side is off

	RequestTimeout time.Duration
	LogLevel       slog.Level

	HTTP          bool // streamable HTTP instead of stdio
	Addr          string
	Path          string
	HTTPAuthToken string // bearer HTTP clients must send; empty means none

	ToolGroups   map[string]bool // enabled groups; core always
	Capabilities map[string]bool // enabled write capabilities
	NoProbe      bool            // skip the startup probe and show everything

	ShowVersion bool
}

// GroupOn reports whether tool group g is enabled.
func (c *Config) GroupOn(g string) bool { return c.ToolGroups[g] }

// LogValue keeps secrets out of logs however the config is printed.
func (c *Config) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.Duration("request_timeout", c.RequestTimeout),
		slog.Bool("http", c.HTTP),
		slog.String("addr", c.Addr),
		slog.Bool("http_auth_set", c.HTTPAuthToken != ""),
		slog.Any("tool_groups", slices.Sorted(maps.Keys(c.ToolGroups))),
		slog.Any("capabilities", slices.Sorted(maps.Keys(c.Capabilities))),
		slog.Bool("no_probe", c.NoProbe),
	}
	if a := c.AD; a != nil {
		attrs = append(attrs, slog.Group("ad",
			slog.String("forest", a.Forest),
			slog.String("bind_user", a.BindUser),
			slog.String("tls", a.TLS),
			slog.String("ca_file", a.CAFile),
			slog.Bool("insecure_skip_verify", a.InsecureSkipVerify),
			slog.String("site", a.Site),
			slog.Any("dcs", a.DCs),
			slog.Any("protected_groups", a.ProtectedGroups),
		))
	}
	if e := c.Entra; e != nil {
		attrs = append(attrs, slog.Group("entra",
			slog.String("tenant", e.Tenant),
			slog.String("client_id", e.ClientID),
			slog.String("cloud", e.Cloud),
			slog.String("login_url", e.LoginURL),
			slog.String("graph_url", e.GraphURL),
			slog.String("password_writeback", e.PasswordWriteback),
		))
	}
	return slog.GroupValue(attrs...)
}

// Parse reads args and the environment. getenv is injected for tests.
// Warnings (non-fatal) are returned for the caller to log once a logger exists.
func Parse(args []string, getenv func(string) string) (*Config, []string, error) {
	var (
		c        Config
		a        AD
		e        Entra
		pwFile   string
		dcs      string
		pgroups  string
		certFile string
		login    string
		graphURL string
		logLevel string
		hauth    string
		groups   string
		caps     string
		stdio    bool
		warnings []string
	)
	clouds := slices.Sorted(maps.Keys(graph.Clouds))

	fs := flag.NewFlagSet("microsoft-directory-mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	str := func(p *string, name, def, usage string) {
		env := "MSDIR_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		fs.StringVar(p, name, cmp.Or(getenv(env), def), usage+" (env "+env+")")
	}
	str(&a.Forest, "ad-forest", "", "forest root DNS name; turns the AD side on")
	str(&a.BindUser, "ad-bind-user", "", "bind account UPN")
	str(&pwFile, "ad-bind-password-file", "", "file holding the bind password")
	str(&a.TLS, "ad-tls", "ldaps", "ldaps|starttls")
	str(&a.CAFile, "ad-ca-file", "", "PEM CA bundle added to the system roots")
	fs.BoolVar(&a.InsecureSkipVerify, "ad-insecure-skip-verify", false, "do not verify domain controller certificates")
	str(&a.Site, "ad-site", "", "AD site: discovery uses its site-scoped SRV records")
	str(&dcs, "ad-dc", "", "comma-separated domain controllers (host or host:port), instead of DNS SRV discovery")
	str(&pgroups, "protected-groups", "", `comma-separated extra AD groups (DOMAIN\name or SID) whose members, direct or nested, writes never touch`)
	str(&e.Tenant, "entra-tenant", "", "tenant ID or domain; turns the Entra side on")
	str(&e.ClientID, "entra-client-id", "", "app registration client ID")
	str(&certFile, "entra-cert-file", "", "PEM file holding the private key and certificate")
	str(&e.Cloud, "entra-cloud", "global", strings.Join(clouds, "|"))
	str(&login, "entra-login-url", "", "login base URL, instead of the cloud's (tests)")
	str(&graphURL, "entra-graph-url", "", "Graph base URL, instead of the cloud's (tests)")
	str(&e.PasswordWriteback, "entra-password-writeback", "unknown", "on|off|unknown, operator-declared (Graph cannot detect it)")
	str(&groups, "tool-groups", strings.Join(Groups, ","), "comma-separated tool groups to enable; core is always on")
	str(&caps, "capabilities", "", "comma-separated write capabilities to enable ("+strings.Join(Capabilities, ", ")+"); none by default")
	fs.BoolVar(&c.NoProbe, "no-probe", false, "skip the startup probe and show every action")
	fs.DurationVar(&c.RequestTimeout, "request-timeout", 30*time.Second, "per-request timeout")
	str(&logLevel, "log-level", "info", "debug|info|warn|error")
	fs.BoolVar(&stdio, "stdio", false, "serve over stdio (default)")
	fs.BoolVar(&c.HTTP, "http", false, "serve over streamable HTTP")
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8235", "HTTP listen address")
	fs.StringVar(&c.Path, "path", "/mcp", "HTTP MCP endpoint path")
	str(&hauth, "http-auth-token-file", "", "file holding the bearer token HTTP clients must send")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stderr)
			fmt.Fprintln(os.Stderr, "Usage: microsoft-directory-mcp [--ad-forest ... | --entra-tenant ...] [flags]")
			fs.PrintDefaults()
		}
		return nil, nil, err
	}
	if c.ShowVersion {
		return &c, nil, nil
	}
	if fs.NArg() > 0 {
		return nil, nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if stdio && c.HTTP {
		return nil, nil, errors.New("--stdio and --http are mutually exclusive")
	}
	if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, nil, fmt.Errorf("--log-level: %w", err)
	}
	c.ToolGroups = map[string]bool{"core": true}
	for g := range strings.SplitSeq(groups, ",") {
		if g = strings.TrimSpace(g); g == "" {
			continue
		}
		if !slices.Contains(Groups, g) {
			return nil, nil, fmt.Errorf("--tool-groups: unknown group %q (want %s)", g, strings.Join(Groups, ", "))
		}
		c.ToolGroups[g] = true
	}
	c.Capabilities = map[string]bool{}
	for w := range strings.SplitSeq(caps, ",") {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		if !slices.Contains(Capabilities, w) {
			return nil, nil, fmt.Errorf("--capabilities: unknown capability %q (want %s)", w, strings.Join(Capabilities, ", "))
		}
		c.Capabilities[w] = true
	}
	if a.Forest == "" && e.Tenant == "" {
		return nil, nil, errors.New("neither side is configured: set --ad-forest, --entra-tenant or both")
	}

	var err error
	if a.Forest != "" {
		switch {
		case a.BindUser == "":
			return nil, nil, errors.New("--ad-bind-user is required with --ad-forest")
		case pwFile == "":
			return nil, nil, errors.New("--ad-bind-password-file is required with --ad-forest")
		case a.TLS != "ldaps" && a.TLS != "starttls":
			return nil, nil, fmt.Errorf("--ad-tls: want ldaps or starttls, got %q", a.TLS)
		}
		for dc := range strings.SplitSeq(dcs, ",") {
			if dc = strings.TrimSpace(dc); dc != "" {
				a.DCs = append(a.DCs, dc)
			}
		}
		for g := range strings.SplitSeq(pgroups, ",") {
			if g = strings.TrimSpace(g); g == "" {
				continue
			}
			if strings.Contains(g, "=") {
				return nil, nil, fmt.Errorf(`--protected-groups: name %q as DOMAIN\name or by SID, not by DN`, g)
			}
			a.ProtectedGroups = append(a.ProtectedGroups, g)
		}
		if a.BindPassword, err = readSecret(pwFile); err != nil {
			return nil, nil, err
		}
		if a.InsecureSkipVerify {
			warnings = append(warnings, "--ad-insecure-skip-verify: TLS verification disabled; domain controller certificates are not checked")
		}
		c.AD = &a
	}

	if e.Tenant != "" {
		switch {
		case e.ClientID == "":
			return nil, nil, errors.New("--entra-client-id is required with --entra-tenant")
		case certFile == "":
			return nil, nil, errors.New("--entra-cert-file is required with --entra-tenant")
		}
		if !slices.Contains([]string{"on", "off", "unknown"}, e.PasswordWriteback) {
			return nil, nil, fmt.Errorf("--entra-password-writeback: want on, off or unknown, got %q", e.PasswordWriteback)
		}
		hosts, ok := graph.Clouds[e.Cloud]
		if !ok {
			return nil, nil, fmt.Errorf("--entra-cloud: unknown cloud %q (want %s)", e.Cloud, strings.Join(clouds, ", "))
		}
		if e.Cloud != "global" && (login != "" || graphURL != "") {
			return nil, nil, errors.New("--entra-login-url and --entra-graph-url are mutually exclusive with a non-default --entra-cloud")
		}
		e.LoginURL, e.GraphURL = hosts.Login, hosts.Graph
		if login != "" {
			if e.LoginURL, err = overrideURL("--entra-login-url", login); err != nil {
				return nil, nil, err
			}
		}
		if graphURL != "" {
			if e.GraphURL, err = overrideURL("--entra-graph-url", graphURL); err != nil {
				return nil, nil, err
			}
		}
		if e.CertPEM, err = os.ReadFile(certFile); err != nil {
			return nil, nil, fmt.Errorf("reading --entra-cert-file: %w", err)
		}
		c.Entra = &e
	}

	if c.HTTP {
		if !strings.HasPrefix(c.Path, "/") {
			return nil, nil, errors.New("--path must start with /")
		}
		if hauth != "" {
			if c.HTTPAuthToken, err = readSecret(hauth); err != nil {
				return nil, nil, err
			}
		}
		if c.HTTPAuthToken == "" && !loopback(c.Addr) {
			return nil, nil, fmt.Errorf("refusing to listen on non-loopback %s without --http-auth-token-file", c.Addr)
		}
	}
	return &c, warnings, nil
}

// overrideURL checks a test URL override. Plain http is only allowed to a
// loopback host (the VM test's stub).
func overrideURL(name, raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("%s must be an https URL, got %q", name, raw)
	}
	if u.Scheme == "http" && !loopback(u.Host) {
		return "", fmt.Errorf("%s must use https unless the host is loopback, got %q", name, raw)
	}
	return u.String(), nil
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return s, nil
}

// loopback reports whether addr ("host:port" or a bare host) is loopback.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
