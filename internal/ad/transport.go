package ad

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Discovery, routing and connections for the whole forest. Referrals are
// never chased: every request goes to a DC of the domain that owns its DN.

// perDCLimit caps the parallel short-lived connections of a per-DC sweep.
const perDCLimit = 4

// addr maps a DC host (from SRV or --ad-dc) to host:port for the TLS mode:
// 636/3269 for LDAPS, 389/3268 for StartTLS. An explicit --ad-dc port is kept
// for the DC itself, never for its GC.
func (c *Client) addr(host string, gc bool) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		if !gc {
			return host
		}
		host = h
	}
	port := "636"
	switch {
	case c.cfg.TLS == "starttls" && gc:
		port = "3268"
	case c.cfg.TLS == "starttls":
		port = "389"
	case gc:
		port = "3269"
	}
	return net.JoinHostPort(strings.TrimSuffix(host, "."), port)
}

// srv resolves an SRV name, narrowed to --ad-site when sited, to addrs.
// SRV records advertise 389/3268, so their ports are ignored.
func (c *Client) srv(ctx context.Context, service, domain string, sited, gc bool) ([]string, error) {
	name := "_" + service + "._tcp." + domain
	if sited && c.cfg.Site != "" {
		name = "_" + service + "._tcp." + c.cfg.Site + "._sites." + domain
	}
	recs, err := c.lookupSRV(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("DNS SRV %s: %w", name, err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, c.addr(r.Target, gc))
	}
	return out, nil
}

// dialFirst dials addrs in order and returns the first that binds.
func (c *Client) dialFirst(ctx context.Context, addrs []string) (Conn, string, error) {
	if len(addrs) == 0 {
		return nil, "", errors.New("no domain controller found")
	}
	var errs []error
	for _, a := range addrs {
		conn, err := c.dial(ctx, a)
		if err == nil {
			return conn, a, nil
		}
		errs = append(errs, err)
	}
	return nil, "", errors.Join(errs...)
}

// each runs fn(0..n-1), at most limit at a time.
func each(n, limit int, fn func(i int)) {
	sem := make(chan struct{}, max(limit, 1))
	var wg sync.WaitGroup
	for i := range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(i)
		})
	}
	wg.Wait()
}

// staticDC is an --ad-dc host with the roles read from it: its domain from
// the rootDSE, GC from its nTDSDSA options.
type staticDC struct {
	addr   string
	domain string // domain DN
	ntds   string // nTDSDSA DN
	gc     bool
}

// detect reads the roles of every --ad-dc host, in flag order, and returns
// the hosts it could not reach. Detected roles are kept; an unreachable host
// is left out and tried again next call.
// ponytail: a dead --ad-dc host costs one dial timeout per call; cache the failure if that bites.
func (c *Client) detect(ctx context.Context) ([]staticDC, []Skipped) {
	c.mu.Lock()
	var todo []string
	for _, h := range c.cfg.DCs {
		if _, ok := c.static[h]; !ok {
			todo = append(todo, h)
		}
	}
	c.mu.Unlock()
	failed := make([]error, len(todo))
	each(len(todo), len(todo), func(i int) {
		var s staticDC
		if s, failed[i] = c.roles(ctx, c.addr(todo[i], false)); failed[i] == nil {
			c.mu.Lock()
			c.static[todo[i]] = s
			c.mu.Unlock()
		}
	})
	var skipped []Skipped
	for i, err := range failed {
		if err != nil {
			skipped = append(skipped, Skipped{DC: c.addr(todo[i], false), Error: err.Error()})
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []staticDC
	for _, h := range c.cfg.DCs {
		if s, ok := c.static[h]; ok {
			out = append(out, s)
		}
	}
	return out, skipped
}

// roles reads one DC's domain from its rootDSE and GC flag from its nTDSDSA options.
func (c *Client) roles(ctx context.Context, addr string) (staticDC, error) {
	conn, err := c.dial(ctx, addr)
	if err != nil {
		return staticDC{}, err
	}
	defer conn.Close()
	root, err := ReadRootDSE(conn)
	if err != nil {
		return staticDC{}, err
	}
	opts, err := readAttr(conn, root.DSServiceName, "options")
	if err != nil {
		return staticDC{}, err
	}
	n, _ := strconv.Atoi(opts)
	return staticDC{addr: addr, domain: root.DefaultNamingContext, ntds: root.DSServiceName, gc: n&1 != 0}, nil // NTDSDSA_OPT_IS_GC
}

// dcs lists d's DCs: the --ad-dc hosts of that domain, or its SRV records.
// sited narrows SRV to --ad-site; a per-DC sweep wants every DC instead. It
// also returns the --ad-dc hosts it could not reach, whose domain is unknown.
func (c *Client) dcs(ctx context.Context, d Domain, sited bool) ([]string, []Skipped, error) {
	if len(c.cfg.DCs) == 0 {
		as, err := c.srv(ctx, "ldap", d.DNS, sited, false)
		return as, nil, err
	}
	var out []string
	ds, dead := c.detect(ctx)
	for _, s := range ds {
		if strings.EqualFold(s.domain, d.DN) {
			out = append(out, s.addr)
		}
	}
	return out, dead, nil
}

// Domains returns the forest's domains from the crossRefs, read once.
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	if c.domains != nil {
		return c.domains, nil
	}
	addrs := make([]string, len(c.cfg.DCs))
	for i, h := range c.cfg.DCs {
		addrs[i] = c.addr(h, false)
	}
	if len(addrs) == 0 {
		var err error
		if addrs, err = c.srv(ctx, "ldap", c.cfg.Forest, true, false); err != nil {
			return nil, err
		}
	}
	conn, _, err := c.dialFirst(ctx, addrs)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	root, err := ReadRootDSE(conn)
	if err != nil {
		return nil, err
	}
	// systemFlags bit 2 (FLAG_CR_NTDS_DOMAIN) marks a domain's crossRef.
	res, err := conn.Search(ldap.NewSearchRequest("CN=Partitions,"+root.ConfigurationNamingContext, ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
		[]string{"dnsRoot", "nETBIOSName", "nCName"}, nil))
	if err != nil {
		return nil, fmt.Errorf("reading crossRefs: %w", err)
	}
	var ds []Domain
	for _, e := range res.Entries {
		ds = append(ds, Domain{e.GetAttributeValue("dnsRoot"), e.GetAttributeValue("nETBIOSName"), e.GetAttributeValue("nCName")})
	}
	if len(ds) == 0 {
		return nil, errors.New("reading crossRefs: no domains")
	}
	// ponytail: read once per process; a domain added to the forest needs a restart.
	c.domains = ds
	return ds, nil
}

// Lookup finds a domain by DNS name, NetBIOS name or DN.
func (c *Client) Lookup(ctx context.Context, name string) (Domain, error) {
	ds, err := c.Domains(ctx)
	if err != nil {
		return Domain{}, err
	}
	for _, d := range ds {
		if strings.EqualFold(name, d.DNS) || strings.EqualFold(name, d.NetBIOS) || strings.EqualFold(name, d.DN) {
			return d, nil
		}
	}
	return Domain{}, fmt.Errorf("no domain %q in the forest", name)
}

// DomainOf routes a DN to the domain that owns it: the longest domain DN it
// ends with. The configuration and schema partitions fall to the root domain.
func (c *Client) DomainOf(ctx context.Context, dn string) (Domain, error) {
	p, err := ldap.ParseDN(dn)
	if err != nil {
		return Domain{}, fmt.Errorf("DN %q: %w", dn, err)
	}
	ds, err := c.Domains(ctx)
	if err != nil {
		return Domain{}, err
	}
	var best Domain
	depth := -1
	for _, d := range ds {
		dp, err := ldap.ParseDN(d.DN)
		if err == nil && len(dp.RDNs) > depth && (dp.EqualFold(p) || dp.AncestorOfFold(p)) {
			best, depth = d, len(dp.RDNs)
		}
	}
	if depth < 0 {
		return Domain{}, fmt.Errorf("no domain of the forest owns %q", dn)
	}
	return best, nil
}

// pooled returns the live pooled connection under key, or dials one of addrs.
func (c *Client) pooled(ctx context.Context, key string, addrs func() ([]string, error)) (Conn, string, error) {
	c.mu.Lock()
	p, ok := c.pool[key]
	c.mu.Unlock()
	if ok && !p.conn.IsClosing() {
		return p.conn, p.addr, nil
	}
	as, err := addrs()
	if err != nil {
		return nil, "", err
	}
	conn, addr, err := c.dialFirst(ctx, as)
	if err != nil {
		return nil, "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if q, ok := c.pool[key]; ok && q != p && !q.conn.IsClosing() {
		conn.Close() // a concurrent caller got there first
		return q.conn, q.addr, nil
	}
	if ok {
		p.conn.Close()
	}
	c.pool[key] = pooled{conn, addr}
	return conn, addr, nil
}

// Conn returns d's pooled connection and the DC it is on, reconnecting when
// it has broken. It is shared: don't close it.
func (c *Client) Conn(ctx context.Context, d Domain) (Conn, string, error) {
	return c.pooled(ctx, d.DN, func() ([]string, error) {
		as, _, err := c.dcs(ctx, d, true)
		return as, err
	})
}

// GC returns the pooled global catalog connection. Use it only to resolve an
// identifier (SID, GUID, UPN) to a DN, then route the DN with DomainOf.
func (c *Client) GC(ctx context.Context) (Conn, string, error) {
	return c.pooled(ctx, "", func() ([]string, error) {
		if len(c.cfg.DCs) == 0 {
			return c.srv(ctx, "gc", c.cfg.Forest, true, true)
		}
		var out []string
		ds, _ := c.detect(ctx)
		for _, s := range ds {
			if s.gc {
				out = append(out, c.addr(s.addr, true))
			}
		}
		return out, nil
	})
}

// Open dials a connection to a DC of d that only the caller uses, for a
// paged search (AD paging cookies belong to one connection). The caller
// closes it.
func (c *Client) Open(ctx context.Context, d Domain) (Conn, string, error) {
	as, _, err := c.dcs(ctx, d, true)
	if err != nil {
		return nil, "", err
	}
	return c.dialFirst(ctx, as)
}

// PDC returns the address of d's PDC emulator: the DC whose nTDSDSA object
// the domain head's fSMORoleOwner names.
func (c *Client) PDC(ctx context.Context, d Domain) (string, error) {
	conn, _, err := c.Conn(ctx, d)
	if err != nil {
		return "", err
	}
	owner, err := readAttr(conn, d.DN, "fSMORoleOwner")
	if err != nil {
		return "", err
	}
	ds, _ := c.detect(ctx)
	for _, s := range ds {
		if strings.EqualFold(s.ntds, owner) {
			return s.addr, nil
		}
	}
	// The server object above "CN=NTDS Settings" holds the DC's host name.
	_, server, _ := strings.Cut(owner, ",")
	host, err := readAttr(conn, server, "dNSHostName")
	if err != nil {
		return "", fmt.Errorf("PDC emulator: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("PDC emulator %s has no dNSHostName", server)
	}
	return c.addr(host, false), nil
}

// Target is the DC a write went to.
type Target struct {
	DC       string `json:"dc"`
	Fallback bool   `json:"fallback,omitempty"` // not the PDC emulator
	Note     string `json:"note,omitempty"`
}

// Write runs fn on a fresh connection to d's PDC emulator, where the write
// and its read-back both go. Only when the dial or bind to the PDC fails,
// before anything is sent, does it fall back to another DC of d. Once fn has
// run there is no second attempt, whatever fn returns.
func (c *Client) Write(ctx context.Context, d Domain, fn func(Conn) error) (Target, error) {
	pdc, err := c.PDC(ctx, d)
	if err != nil {
		return Target{}, err
	}
	t := Target{DC: pdc}
	conn, err := c.dial(ctx, pdc)
	if err != nil {
		as, _, lerr := c.dcs(ctx, d, false) // any site
		var others []string
		for _, a := range as {
			if !strings.EqualFold(a, pdc) {
				others = append(others, a)
			}
		}
		if lerr == nil {
			conn, t.DC, lerr = c.dialFirst(ctx, others)
		}
		if lerr != nil {
			return Target{DC: pdc}, fmt.Errorf("PDC emulator: %w; no other DC of %s: %w", err, d.DNS, lerr)
		}
		t.Fallback = true
		t.Note = fmt.Sprintf("PDC emulator %s unreachable (%v); written to %s, which other DCs see only after replication", pdc, err, t.DC)
	}
	defer conn.Close()
	return t, fn(conn)
}

// Skipped is a domain or DC left out of a call because it was unreachable.
type Skipped struct {
	Domain string `json:"domain,omitempty"`
	DC     string `json:"dc,omitempty"`
	Error  string `json:"error"`
}

// unreachable reports whether err means the connection, not the request, failed.
func unreachable(err error) bool { return ldap.IsErrorWithCode(err, ldap.ErrorNetwork) }

// FanOut runs fn against each domain's pooled connection in parallel, or
// only the domain named by domain. A domain that can't be reached is skipped;
// any other error fails the call. Results are unsorted.
func FanOut[T any](ctx context.Context, c *Client, domain string, fn func(Conn, Domain) ([]T, error)) ([]T, []Skipped, error) {
	ds, err := c.pick(ctx, domain)
	if err != nil {
		return nil, nil, err
	}
	var (
		mu      sync.Mutex
		out     []T
		skipped []Skipped
		errs    []error
	)
	each(len(ds), len(ds), func(i int) {
		conn, _, err := c.Conn(ctx, ds[i])
		var r []T
		if err == nil {
			r, err = fn(conn, ds[i])
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			out = append(out, r...)
		case conn == nil || unreachable(err):
			skipped = append(skipped, Skipped{Domain: ds[i].DNS, Error: err.Error()})
		default:
			errs = append(errs, fmt.Errorf("%s: %w", ds[i].DNS, err))
		}
	})
	return out, skipped, errors.Join(errs...)
}

// PerDC opens a short-lived connection to every DC of d (not just --ad-site's),
// a few at a time within ctx's deadline, runs fn on each and closes them. A DC
// that can't be reached is skipped; any other error fails the call.
func PerDC[T any](ctx context.Context, c *Client, d Domain, fn func(conn Conn, dc string) (T, error)) ([]T, []Skipped, error) {
	as, skipped, err := c.dcs(ctx, d, false)
	if err != nil {
		return nil, nil, err
	}
	var (
		mu   sync.Mutex
		out  []T
		errs []error
	)
	each(len(as), perDCLimit, func(i int) {
		var (
			r    T
			conn Conn
		)
		err := ctx.Err()
		if err == nil {
			if conn, err = c.dial(ctx, as[i]); err == nil {
				defer conn.Close()
				if dl, ok := ctx.Deadline(); ok {
					conn.SetTimeout(min(c.timeout, time.Until(dl)))
				}
				r, err = fn(conn, as[i])
			}
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			out = append(out, r)
		case conn == nil || unreachable(err):
			skipped = append(skipped, Skipped{DC: as[i], Error: err.Error()})
		default:
			errs = append(errs, fmt.Errorf("%s: %w", as[i], err))
		}
	})
	return out, skipped, errors.Join(errs...)
}

// DomainStatus is ad_status's view of one domain.
type DomainStatus struct {
	Domain       string `json:"domain"`
	DC           string `json:"dc,omitempty"` // the DC serving reads
	PDC          string `json:"pdc,omitempty"`
	PDCReachable bool   `json:"pdc_reachable"`
	Error        string `json:"error,omitempty"`
}

// Status reports, for every domain, the DC serving it and whether its PDC
// emulator can be dialed and bound.
func (c *Client) Status(ctx context.Context) ([]DomainStatus, error) {
	ds, err := c.Domains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DomainStatus, len(ds))
	each(len(ds), len(ds), func(i int) {
		s := &out[i]
		s.Domain = ds[i].DNS
		_, dc, err := c.Conn(ctx, ds[i])
		s.DC = dc
		if err == nil {
			s.PDC, err = c.PDC(ctx, ds[i])
		}
		if err == nil {
			var conn Conn
			if conn, err = c.dial(ctx, s.PDC); err == nil {
				conn.Close()
				s.PDCReachable = true
			}
		}
		if err != nil {
			s.Error = err.Error()
		}
	})
	return out, nil
}
