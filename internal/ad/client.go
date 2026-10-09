// Package ad talks to the forest over LDAP with TLS. See docs/adr/0003.
package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
)

type Client struct {
	cfg     *config.AD
	roots   *x509.CertPool
	timeout time.Duration
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
	return &Client{cfg: cfg, roots: roots, timeout: timeout}, nil
}

// dc is the domain controller to use, as host:port for the TLS mode.
// ponytail: first static host only; discovery and failover come with the AD transport issue.
func (c *Client) dc() (host, addr string) {
	host = c.cfg.DCs[0]
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h, host
	}
	port := "636"
	if c.cfg.TLS == "starttls" {
		port = "389"
	}
	return host, net.JoinHostPort(host, port)
}

// Dial connects over TLS (LDAPS or StartTLS, never plain) and simple-binds.
// The DC is returned even when the dial or bind fails.
func (c *Client) Dial(ctx context.Context) (*ldap.Conn, string, error) {
	host, addr := c.dc()
	tc := &tls.Config{ServerName: host, RootCAs: c.roots, InsecureSkipVerify: c.cfg.InsecureSkipVerify, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: c.timeout}
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
		return nil, addr, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	conn.SetTimeout(c.timeout)
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}
	if err := conn.Bind(c.cfg.BindUser, c.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, addr, fmt.Errorf("bind as %s: %w", c.cfg.BindUser, err)
	}
	return conn, addr, nil
}

// RootDSE holds the rootDSE naming contexts.
type RootDSE struct {
	DefaultNamingContext       string   `json:"default_naming_context"`
	RootDomainNamingContext    string   `json:"root_domain_naming_context"`
	ConfigurationNamingContext string   `json:"configuration_naming_context"`
	SchemaNamingContext        string   `json:"schema_naming_context"`
	NamingContexts             []string `json:"naming_contexts"`
	DNSHostName                string   `json:"dns_host_name,omitempty"`
}

// ReadRootDSE reads the naming contexts on a bound connection.
func ReadRootDSE(conn *ldap.Conn) (*RootDSE, error) {
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
			"schemaNamingContext", "namingContexts", "dnsHostName"}, nil))
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
	}, nil
}
