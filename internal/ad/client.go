// Package ad talks to the forest over LDAP with TLS. See docs/adr/0003.
package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
)

// Conn is the part of *ldap.Conn the transport uses; tests fake it.
type Conn interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	IsClosing() bool
	SetTimeout(time.Duration)
	Close() error
}

type Client struct {
	cfg     *config.AD
	roots   *x509.CertPool
	timeout time.Duration

	// Seams for tests: dial connects and binds; lookupSRV resolves one SRV name.
	dial      func(ctx context.Context, addr string) (Conn, error)
	lookupSRV func(ctx context.Context, name string) ([]*net.SRV, error)

	loadMu  sync.Mutex
	domains []Domain // from the crossRefs, once read

	mu     sync.Mutex
	pool   map[string]pooled   // domain DN, or "" for the GC
	static map[string]staticDC // --ad-dc host to its detected roles
}

type pooled struct {
	conn Conn
	addr string
}

// New loads --ad-ca-file into a copy of the system roots.
func New(cfg *config.AD, timeout time.Duration) (*Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("--ad-ca-file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ad-ca-file %s: no PEM certificates", cfg.CAFile)
		}
	}
	c := &Client{cfg: cfg, roots: roots, timeout: timeout, pool: map[string]pooled{}, static: map[string]staticDC{}}
	c.dial = c.dialTLS
	c.lookupSRV = func(ctx context.Context, name string) ([]*net.SRV, error) {
		_, srv, err := net.DefaultResolver.LookupSRV(ctx, "", "", name)
		return srv, err
	}
	return c, nil
}

// dialTLS connects over TLS (LDAPS or StartTLS, never plain) and simple-binds.
func (c *Client) dialTLS(ctx context.Context, addr string) (Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	tc := &tls.Config{ServerName: host, RootCAs: c.roots, InsecureSkipVerify: c.cfg.InsecureSkipVerify, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: c.timeout}
	d.Deadline, _ = ctx.Deadline()
	var (
		conn *ldap.Conn
		err  error
	)
	if c.cfg.TLS == "starttls" {
		conn, err = ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(d))
		if err == nil {
			if err = conn.StartTLS(tc); err != nil {
				conn.Close()
			}
		}
	} else {
		conn, err = ldap.DialURL("ldaps://"+addr, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(tc))
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	// Pooled connections outlive the call that dialed them, so each request
	// gets --request-timeout rather than this call's deadline.
	conn.SetTimeout(c.timeout)
	if err := conn.Bind(c.cfg.BindUser, c.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind to %s as %s: %w", addr, c.cfg.BindUser, err)
	}
	return conn, nil
}

// RootDSE holds the rootDSE naming contexts.
type RootDSE struct {
	DefaultNamingContext       string   `json:"default_naming_context"`
	RootDomainNamingContext    string   `json:"root_domain_naming_context"`
	ConfigurationNamingContext string   `json:"configuration_naming_context"`
	SchemaNamingContext        string   `json:"schema_naming_context"`
	NamingContexts             []string `json:"naming_contexts"`
	DNSHostName                string   `json:"dns_host_name,omitempty"`
	DSServiceName              string   `json:"ds_service_name,omitempty"` // this DC's nTDSDSA object
}

// ReadRootDSE reads the naming contexts on a bound connection.
func ReadRootDSE(conn Conn) (*RootDSE, error) {
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
			"schemaNamingContext", "namingContexts", "dnsHostName", "dsServiceName"}, nil))
	if err != nil {
		return nil, fmt.Errorf("reading rootDSE: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("reading rootDSE: %d entries", len(res.Entries))
	}
	e := res.Entries[0]
	return &RootDSE{
		DefaultNamingContext:       e.GetAttributeValue("defaultNamingContext"),
		RootDomainNamingContext:    e.GetAttributeValue("rootDomainNamingContext"),
		ConfigurationNamingContext: e.GetAttributeValue("configurationNamingContext"),
		SchemaNamingContext:        e.GetAttributeValue("schemaNamingContext"),
		NamingContexts:             e.GetAttributeValues("namingContexts"),
		DNSHostName:                e.GetAttributeValue("dnsHostName"),
		DSServiceName:              e.GetAttributeValue("dsServiceName"),
	}, nil
}

// readAttr reads one attribute of one object.
func readAttr(conn Conn, dn, attr string) (string, error) {
	res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{attr}, nil))
	if err != nil {
		return "", fmt.Errorf("reading %s of %s: %w", attr, dn, err)
	}
	if len(res.Entries) != 1 {
		return "", fmt.Errorf("reading %s of %s: %d entries", attr, dn, len(res.Entries))
	}
	return res.Entries[0].GetAttributeValue(attr), nil
}

// Domain is one domain of the forest, from its crossRef.
type Domain struct {
	DNS     string `json:"dns"`
	NetBIOS string `json:"netbios"`
	DN      string `json:"dn"`
}

// ReadProbe checks one right the bind account may lack (for example
// "pso-read"). It returns an error only when the right is missing; actions
// that name it are then hidden.
type ReadProbe func(conn Conn, root *RootDSE) error

// ReadProbes are the named read probes the startup probe runs. Tool issues
// register theirs here.
var ReadProbes = map[string]ReadProbe{}

// Probe is what the startup probe learned. A nil *Probe (--no-probe) shows
// everything, and so does a failed bind.
type Probe struct {
	Bound   bool              `json:"bound"`
	DC      string            `json:"dc"`
	Domains []Domain          `json:"domains,omitempty"`
	Reads   map[string]string `json:"reads,omitempty"` // read probe name to "ok" or why it failed
	Note    string            `json:"note,omitempty"`
}

// Probe reads the domain crossRefs, binds to a DC of the forest root domain
// and runs every ReadProbe there.
func (c *Client) Probe(ctx context.Context) *Probe {
	p := &Probe{}
	conn, dc, root, err := c.Root(ctx)
	p.DC = dc
	if err != nil {
		p.Note = err.Error()
		return p
	}
	p.Bound = true
	p.Domains, _ = c.Domains(ctx)
	p.Reads = map[string]string{}
	for name, rp := range ReadProbes {
		p.Reads[name] = "ok"
		if err := rp(conn, root); err != nil {
			p.Reads[name] = err.Error()
		}
	}
	return p
}

// Root returns the pooled connection to the forest root domain and its rootDSE.
func (c *Client) Root(ctx context.Context) (Conn, string, *RootDSE, error) {
	d, err := c.Lookup(ctx, c.cfg.Forest)
	if err != nil {
		return nil, "", nil, err
	}
	conn, dc, err := c.Conn(ctx, d)
	if err != nil {
		return nil, dc, nil, err
	}
	root, err := ReadRootDSE(conn)
	return conn, dc, root, err
}
