package ad

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/paging"
)

// cursorIdle is under AD's 900 s MaxConnIdleTime.
const cursorIdle = 10 * time.Minute

// Query is a paged search, domain by domain. With Base it searches only
// under that DN, in the domain owning it; otherwise under each domain head
// (the Under RDNs prefixed), or only the domain named by Domain.
type Query struct {
	Domain      string   `json:"domain,omitempty"`
	Base        string   `json:"base,omitempty"`
	Under       string   `json:"under,omitempty"` // e.g. "CN=Deleted Objects"
	Scope       int      `json:"scope,omitempty"` // default subtree
	Filter      string   `json:"filter"`
	Attrs       []string `json:"attrs,omitempty"`
	ShowDeleted bool     `json:"show_deleted,omitempty"`
	// Shape renders a decoded entry; the default keeps it as decoded.
	Shape func(map[string]any) map[string]any `json:"-"`
}

// Page is one page of results.
type Page struct {
	Results    []map[string]any   `json:"results"`
	NextCursor string             `json:"next_cursor,omitempty"`
	Truncation *paging.Truncation `json:"_truncation,omitempty"`
	Skipped    []Skipped          `json:"_skipped,omitempty"`
}

// paged is a search in progress: the connection its paging cookie belongs
// to, which domain it is in, and results already read but not yet returned.
type paged struct {
	key     string
	q       Query
	domains []Domain
	idx     int
	conn    Conn
	cookie  []byte
	pending []map[string]any
	used    time.Time
}

func (p *paged) close() {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

var errExpired = errors.New("cursor expired, re-run the search")

// Search returns one page of q: a new search when cursor is "", else the
// next page of the search that returned it. The cursor pins a connection
// and expires after 10 idle minutes, when that connection breaks, or on
// restart. Results are unsorted. It walks the domains itself rather than
// through FanOut: a paging cookie belongs to one connection, held between calls.
func (c *Client) Search(ctx context.Context, q Query, cursor string) (*Page, error) {
	kb, _ := json.Marshal(q)
	sum := sha256.Sum256(kb)
	key := hex.EncodeToString(sum[:8])
	p, err := c.take(cursor, key)
	if err != nil {
		return nil, err
	}
	if p == nil {
		p = &paged{key: key, q: q}
		if p.domains, err = c.queryDomains(ctx, q); err != nil {
			return nil, err
		}
	}
	page := &Page{Results: []map[string]any{}}
	out := p.pending
	p.pending = nil
	for len(out) < paging.Size && p.idx < len(p.domains) {
		d := p.domains[p.idx]
		if p.conn == nil {
			if p.conn, _, err = c.Open(ctx, d); err != nil {
				page.Skipped = append(page.Skipped, Skipped{Domain: d.DNS, Error: err.Error()})
				p.idx++
				continue
			}
		}
		res, err := p.conn.Search(p.request(d, paging.Size-len(out)))
		if err != nil {
			p.close()
			switch {
			case p.cookie != nil && unreachable(err):
				return nil, fmt.Errorf("%w (connection to %s lost)", errExpired, d.DNS)
			case unreachable(err):
				page.Skipped = append(page.Skipped, Skipped{Domain: d.DNS, Error: err.Error()})
				p.idx++
				continue
			}
			return nil, fmt.Errorf("%s: %w", d.DNS, err)
		}
		for _, e := range res.Entries {
			m := Decode(e, q.Attrs)
			if q.Shape != nil {
				m = q.Shape(m)
			}
			out = append(out, m)
		}
		p.cookie = nil
		if pc, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok && len(pc.Cookie) > 0 {
			p.cookie = pc.Cookie
		} else {
			p.close()
			p.idx++
		}
	}
	var kept int
	kept, page.Truncation = paging.Trim(out)
	p.pending = out[kept:]
	page.Results = append(page.Results, out[:kept]...)
	if p.idx < len(p.domains) || len(p.pending) > 0 {
		page.NextCursor = c.keep(p)
	}
	return page, nil
}

func (p *paged) request(d Domain, size int) *ldap.SearchRequest {
	base := d.DN
	switch {
	case p.q.Base != "":
		base = p.q.Base
	case p.q.Under != "":
		base = p.q.Under + "," + d.DN
	}
	paging := ldap.NewControlPaging(uint32(size))
	paging.SetCookie(p.cookie)
	controls := []ldap.Control{paging}
	if p.q.ShowDeleted {
		controls = append(controls, ldap.NewControlMicrosoftShowDeleted())
	}
	scope := p.q.Scope
	if scope == 0 {
		scope = ldap.ScopeWholeSubtree
	}
	return ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, p.q.Filter, p.q.Attrs, controls)
}

func (c *Client) queryDomains(ctx context.Context, q Query) ([]Domain, error) {
	switch {
	case q.Base != "":
		d, err := c.DomainOf(ctx, q.Base)
		return []Domain{d}, err
	case q.Domain != "":
		d, err := c.Lookup(ctx, q.Domain)
		return []Domain{d}, err
	}
	return c.Domains(ctx)
}

// take removes the search behind cursor from the store, so two callers
// can't page it at once, and closes any that have gone idle.
// ponytail: idle cursors are reaped only when a search runs; AD drops their connections anyway.
func (c *Client) take(cursor, key string) (*paged, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for id, p := range c.cursors {
		if now.Sub(p.used) > cursorIdle {
			p.close()
			delete(c.cursors, id)
		}
	}
	if cursor == "" {
		return nil, nil
	}
	p, ok := c.cursors[cursor]
	switch {
	case !ok:
		return nil, errExpired
	case p.key != key:
		return nil, paging.ErrForeignCursor
	case p.conn != nil && p.conn.IsClosing():
		p.close()
		delete(c.cursors, cursor)
		return nil, errExpired
	}
	delete(c.cursors, cursor)
	return p, nil
}

// keep stores p under a fresh random cursor.
func (c *Client) keep(p *paged) string {
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	p.used = c.now()
	c.cursors[id] = p
	return id
}
