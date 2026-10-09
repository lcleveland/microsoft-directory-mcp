package ad

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
)

// A fake two-domain forest: corp.example.com (dc1 GC, dc2 PDC) and its child
// child.corp.example.com (dc3 PDC, dc4). Every DC sees every entry.
const (
	corpDN  = "DC=corp,DC=example,DC=com"
	childDN = "DC=child," + corpDN
	confDN  = "CN=Configuration," + corpDN
	sites   = "CN=Servers,CN=Site1,CN=Sites," + confDN
)

type fakeDir struct {
	mu       sync.Mutex
	dead     map[string]bool // host
	busy     map[string]bool // host refusing new connections; open ones keep working
	dials    []string        // addrs
	searches []string        // "host base filter"
	srv      map[string][]string
	tree     map[string]map[string][]string // lowercased DN to attributes
	roots    map[string]map[string][]string // host to rootDSE
	local    map[string]map[string][]string // "host dn" (dn lowercased) to attributes only that DC holds
}

func ntds(dc string) string { return "CN=NTDS Settings,CN=" + strings.ToUpper(dc) + "," + sites }

func newFakeDir() *fakeDir {
	f := &fakeDir{dead: map[string]bool{}, busy: map[string]bool{}, tree: map[string]map[string][]string{}, roots: map[string]map[string][]string{},
		local: map[string]map[string][]string{},
		srv: map[string][]string{
			"_ldap._tcp.corp.example.com":                    {"dc1.corp.example.com", "dc2.corp.example.com"},
			"_ldap._tcp.Site1._sites.corp.example.com":       {"dc2.corp.example.com"},
			"_ldap._tcp.child.corp.example.com":              {"dc4.child.corp.example.com", "dc3.child.corp.example.com"},
			"_ldap._tcp.Site1._sites.child.corp.example.com": {"dc3.child.corp.example.com"},
			"_gc._tcp.corp.example.com":                      {"dc1.corp.example.com"},
			"_gc._tcp.Site1._sites.corp.example.com":         {"dc1.corp.example.com"},
		}}
	add := func(dn string, attrs map[string][]string) { f.tree[strings.ToLower(dn)] = attrs }
	add("CN=CORP,CN=Partitions,"+confDN, map[string][]string{"dnsRoot": {"corp.example.com"}, "nETBIOSName": {"CORP"}, "nCName": {corpDN}, "systemFlags": {"3"}, "objectClass": {"crossRef"}})
	add("CN=CHILD,CN=Partitions,"+confDN, map[string][]string{"dnsRoot": {"child.corp.example.com"}, "nETBIOSName": {"CHILD"}, "nCName": {childDN}, "systemFlags": {"3"}, "objectClass": {"crossRef"}})
	add(corpDN, map[string][]string{"fSMORoleOwner": {ntds("dc2")}})
	add(childDN, map[string][]string{"fSMORoleOwner": {ntds("dc3")}})
	for dc, d := range map[string]string{"dc1": "corp.example.com", "dc2": "corp.example.com", "dc3": "child.corp.example.com", "dc4": "child.corp.example.com"} {
		opts := "0"
		if dc == "dc1" {
			opts = "1"
		}
		dn := corpDN
		if d != "corp.example.com" {
			dn = childDN
		}
		add(ntds(dc), map[string][]string{"objectClass": {"top", "applicationSettings", "nTDSDSA"}, "options": {opts},
			"msDS-hasMasterNCs": {dn, confDN}, "invocationId": {string(invocation(dc))}})
		add("CN="+strings.ToUpper(dc)+","+sites, map[string][]string{"objectClass": {"top", "server"}, "dNSHostName": {dc + "." + d}})
		f.roots[dc+"."+d] = map[string][]string{"defaultNamingContext": {dn}, "rootDomainNamingContext": {corpDN},
			"configurationNamingContext": {confDN}, "dsServiceName": {ntds(dc)}, "dnsHostName": {dc + "." + d}}
	}
	return f
}

// invocation is a made-up invocationId per DC: 16 bytes of its last digit.
func invocation(dc string) []byte { return []byte(strings.Repeat(dc[len(dc)-1:], 16)) }

func (f *fakeDir) client(cfg *config.AD) *Client {
	c, err := New(cfg, 0)
	if err != nil {
		panic(err)
	}
	c.dial = func(_ context.Context, addr string) (Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.dials = append(f.dials, addr)
		if f.dead[host] || f.busy[host] {
			return nil, errors.New("connecting to " + addr + ": connection refused")
		}
		return &fakeConn{f: f, host: host, addr: addr}, nil
	}
	c.lookupSRV = func(_ context.Context, name string) ([]*net.SRV, error) {
		hosts, ok := f.srv[name]
		if !ok {
			return nil, errors.New("no such host " + name)
		}
		var out []*net.SRV
		for _, h := range hosts {
			out = append(out, &net.SRV{Target: h + ".", Port: 389})
		}
		return out, nil
	}
	return c
}

func (f *fakeDir) kill(hosts ...string) {
	for _, h := range hosts {
		f.dead[h] = true
	}
}

type fakeConn struct {
	f      *fakeDir
	host   string
	addr   string
	closed bool
}

func (c *fakeConn) IsClosing() bool          { return c.closed || c.f.dead[c.host] }
func (c *fakeConn) Close() error             { c.closed = true; return nil }
func (c *fakeConn) SetTimeout(time.Duration) {}

func srvConfig() *config.AD { return &config.AD{Forest: "corp.example.com", TLS: "ldaps"} }

func TestDomainOf(t *testing.T) {
	c := newFakeDir().client(srvConfig())
	ctx := context.Background()
	for dn, want := range map[string]string{
		"CN=u,OU=x," + childDN:                     "child.corp.example.com",
		"CN=u,OU=x," + corpDN:                      "corp.example.com",
		"cn=u, dc=CHILD,dc=Corp,dc=example,dc=com": "child.corp.example.com",
		corpDN:                    "corp.example.com",
		"CN=Partitions," + confDN: "corp.example.com",
	} {
		d, err := c.DomainOf(ctx, dn)
		if err != nil || d.DNS != want {
			t.Errorf("%s: want %s, got %+v %v", dn, want, d, err)
		}
	}
	if _, err := c.DomainOf(ctx, "CN=u,DC=other,DC=com"); err == nil {
		t.Error("foreign DN: want an error")
	}
	if _, err := c.DomainOf(ctx, "not a dn"); err == nil {
		t.Error("bad DN: want an error")
	}
}

func TestFanOutSkipsDeadDomain(t *testing.T) {
	f := newFakeDir()
	f.kill("dc3.child.corp.example.com", "dc4.child.corp.example.com")
	c := f.client(srvConfig())
	ctx := context.Background()
	search := func(conn Conn, d Domain) ([]string, error) {
		res, err := conn.Search(ldap.NewSearchRequest(d.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
		if err != nil {
			return nil, err
		}
		return []string{d.DNS + ":" + res.Entries[0].DN}, nil
	}
	got, skipped, err := FanOut(ctx, c, "", search)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"corp.example.com:" + strings.ToLower(corpDN)}) {
		t.Errorf("results: %v", got)
	}
	if len(skipped) != 1 || skipped[0].Domain != "child.corp.example.com" || !strings.Contains(skipped[0].Error, "refused") {
		t.Errorf("skipped: %+v", skipped)
	}
	// Named by NetBIOS name: only that domain.
	got, skipped, err = FanOut(ctx, c, "child", search)
	if err != nil || len(got) != 0 || len(skipped) != 1 {
		t.Errorf("child only: %v %+v %v", got, skipped, err)
	}
	if _, _, err := FanOut(ctx, c, "nope", search); err == nil {
		t.Error("unknown domain: want an error")
	}
	// A search error fails the call rather than skipping.
	boom := errors.New("bad filter")
	if _, _, err := FanOut(ctx, c, "corp.example.com", func(Conn, Domain) ([]string, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("search error: %v", err)
	}
}

func TestPooledConnReconnects(t *testing.T) {
	f := newFakeDir()
	c := f.client(srvConfig())
	ctx := context.Background()
	d, _ := c.Lookup(ctx, "corp.example.com")
	a, dc, err := c.Conn(ctx, d)
	if err != nil || dc != "dc1.corp.example.com:636" {
		t.Fatal(dc, err)
	}
	if b, _, _ := c.Conn(ctx, d); b != a {
		t.Error("second call should reuse the pooled connection")
	}
	f.kill("dc1.corp.example.com")
	if _, dc, err = c.Conn(ctx, d); err != nil || dc != "dc2.corp.example.com:636" {
		t.Errorf("after dc1 broke: %s %v", dc, err)
	}
	if _, dc, err := c.GC(ctx); err == nil {
		t.Errorf("GC: dc1 is the only GC and is dead, got %s", dc)
	}
}

func TestSiteNarrowsDiscovery(t *testing.T) {
	cfg := srvConfig()
	cfg.Site = "Site1"
	cfg.TLS = "starttls"
	c := newFakeDir().client(cfg)
	ctx := context.Background()
	d, _ := c.Lookup(ctx, "corp.example.com")
	if _, dc, err := c.Conn(ctx, d); err != nil || dc != "dc2.corp.example.com:389" {
		t.Errorf("sited DC: %s %v", dc, err)
	}
	if _, dc, err := c.GC(ctx); err != nil || dc != "dc1.corp.example.com:3268" {
		t.Errorf("sited GC: %s %v", dc, err)
	}
}

func TestPDCPerDomain(t *testing.T) {
	c := newFakeDir().client(srvConfig())
	ctx := context.Background()
	for name, want := range map[string]string{"corp": "dc2.corp.example.com:636", "child": "dc3.child.corp.example.com:636"} {
		d, _ := c.Lookup(ctx, name)
		if pdc, err := c.PDC(ctx, d); err != nil || pdc != want {
			t.Errorf("%s: want %s, got %s %v", name, want, pdc, err)
		}
	}
}

func TestWriteFallback(t *testing.T) {
	ctx := context.Background()
	ok := func(Conn) error { return nil }

	f := newFakeDir()
	c := f.client(srvConfig())
	d, _ := c.Lookup(ctx, "corp")
	tgt, err := c.Write(ctx, d, ok)
	if err != nil || tgt != (Target{DC: "dc2.corp.example.com:636"}) {
		t.Errorf("PDC up: %+v %v", tgt, err)
	}

	// Dial to the PDC fails before anything is sent: another DC of the domain.
	f.kill("dc2.corp.example.com")
	tgt, err = c.Write(ctx, d, ok)
	if err != nil || tgt.DC != "dc1.corp.example.com:636" || !tgt.Fallback || !strings.Contains(tgt.Note, "replicat") {
		t.Errorf("PDC down: %+v %v", tgt, err)
	}

	// The PDC took the request and failed: no second attempt anywhere.
	f = newFakeDir()
	c = f.client(srvConfig())
	d, _ = c.Lookup(ctx, "corp")
	calls := 0
	boom := ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))
	tgt, err = c.Write(ctx, d, func(Conn) error { calls++; return boom })
	if !errors.Is(err, boom) || calls != 1 || tgt.Fallback || tgt.DC != "dc2.corp.example.com:636" {
		t.Errorf("send error: %+v %v calls=%d", tgt, err, calls)
	}
}

func TestPerDC(t *testing.T) {
	f := newFakeDir()
	f.kill("dc4.child.corp.example.com")
	c := f.client(srvConfig())
	ctx := context.Background()
	d, _ := c.Lookup(ctx, "child")
	got, skipped, err := PerDC(ctx, c, d, func(_ Conn, dc string) (string, error) { return dc, nil })
	if err != nil || !slices.Equal(got, []string{"dc3.child.corp.example.com:636"}) {
		t.Errorf("results: %v %v", got, err)
	}
	if len(skipped) != 1 || skipped[0].DC != "dc4.child.corp.example.com:636" {
		t.Errorf("skipped: %+v", skipped)
	}
}

func TestStaticDCRoles(t *testing.T) {
	f := newFakeDir()
	f.srv = nil // --ad-dc never looks up SRV
	cfg := srvConfig()
	cfg.DCs = []string{"dc1.corp.example.com", "dc2.corp.example.com:1636", "dc3.child.corp.example.com", "dc4.child.corp.example.com"}
	c := f.client(cfg)
	ctx := context.Background()

	roles, dead := c.detect(ctx)
	if dead != nil {
		t.Errorf("dead: %+v", dead)
	}
	want := []staticDC{
		{addr: "dc1.corp.example.com:636", domain: corpDN, ntds: ntds("dc1"), gc: true},
		{addr: "dc2.corp.example.com:1636", domain: corpDN, ntds: ntds("dc2")},
		{addr: "dc3.child.corp.example.com:636", domain: childDN, ntds: ntds("dc3")},
		{addr: "dc4.child.corp.example.com:636", domain: childDN, ntds: ntds("dc4")},
	}
	if !slices.Equal(roles, want) {
		t.Errorf("roles:\n got %+v\nwant %+v", roles, want)
	}
	corp, err := c.Lookup(ctx, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if pdc, err := c.PDC(ctx, corp); err != nil || pdc != "dc2.corp.example.com:1636" {
		t.Errorf("PDC: %s %v", pdc, err)
	}
	if _, dc, err := c.GC(ctx); err != nil || dc != "dc1.corp.example.com:3269" {
		t.Errorf("GC: %s %v", dc, err)
	}
	child, _ := c.Lookup(ctx, "child")
	if _, dc, err := c.Conn(ctx, child); err != nil || dc != "dc3.child.corp.example.com:636" {
		t.Errorf("child DC: %s %v", dc, err)
	}
}

func TestPerDCStaticSkipsUndetected(t *testing.T) {
	f := newFakeDir()
	f.kill("dc4.child.corp.example.com")
	cfg := srvConfig()
	cfg.DCs = []string{"dc1.corp.example.com", "dc3.child.corp.example.com", "dc4.child.corp.example.com"}
	c := f.client(cfg)
	ctx := context.Background()
	d, _ := c.Lookup(ctx, "child")
	got, skipped, err := PerDC(ctx, c, d, func(_ Conn, dc string) (string, error) { return dc, nil })
	if err != nil || !slices.Equal(got, []string{"dc3.child.corp.example.com:636"}) {
		t.Errorf("results: %v %v", got, err)
	}
	if len(skipped) != 1 || skipped[0].DC != "dc4.child.corp.example.com:636" {
		t.Errorf("skipped: %+v", skipped)
	}
}

func TestWriteFallbackLeavesSite(t *testing.T) {
	f := newFakeDir()
	cfg := srvConfig()
	cfg.Site = "Site1" // Site1 holds only dc2, the PDC
	c := f.client(cfg)
	ctx := context.Background()
	d, _ := c.Lookup(ctx, "corp")
	if _, _, err := c.Conn(ctx, d); err != nil { // reads pooled on dc2
		t.Fatal(err)
	}
	f.busy["dc2.corp.example.com"] = true
	tgt, err := c.Write(ctx, d, func(Conn) error { return nil })
	if err != nil || tgt.DC != "dc1.corp.example.com:636" || !tgt.Fallback {
		t.Errorf("%+v %v", tgt, err)
	}
}
