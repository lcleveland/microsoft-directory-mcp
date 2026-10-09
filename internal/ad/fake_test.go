package ad

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// nc is the naming context holding dn: a DC returns a referral, not
// entries, for a subtree search reaching into another one; the GC doesn't.
func nc(dn string) string {
	for _, n := range []string{childDN, confDN, corpDN} {
		if n = strings.ToLower(n); dn == n || strings.HasSuffix(dn, ","+n) {
			return n
		}
	}
	return ""
}

// Search serves the fake tree: base, one-level and subtree scopes (base ""
// with subtree is a GC search of the whole forest), filters, the paged
// search and show-deleted controls, and member;range=a-b retrieval.
func (c *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.IsClosing() {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("connection closed"))
	}
	c.f.mu.Lock()
	c.f.searches = append(c.f.searches, c.addr+" "+req.BaseDN+" "+req.Filter)
	c.f.mu.Unlock()
	res := &ldap.SearchResult{}
	if req.BaseDN == "" && req.Scope == ldap.ScopeBaseObject {
		res.Entries = append(res.Entries, ldap.NewEntry("", c.f.roots[c.host]))
		return res, nil
	}
	base := strings.ToLower(req.BaseDN)
	if _, ok := c.f.tree[base]; !ok && req.Scope == ldap.ScopeBaseObject {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	showDeleted := ldap.FindControl(req.Controls, ldap.ControlTypeMicrosoftShowDeleted) != nil
	var dns []string
	for dn, attrs := range c.f.tree {
		_, parent, _ := strings.Cut(dn, ",")
		var in bool
		switch req.Scope {
		case ldap.ScopeBaseObject:
			in = dn == base
		case ldap.ScopeSingleLevel:
			in = parent == base
		default:
			in = base == "" || dn == base || strings.HasSuffix(dn, ","+base)
		}
		gc := strings.HasSuffix(c.addr, ":3269")
		if req.Scope == ldap.ScopeWholeSubtree && !gc && nc(dn) != nc(base) {
			continue
		}
		deleted := len(attrs["isDeleted"]) > 0 && attrs["isDeleted"][0] == "TRUE"
		if in && (showDeleted || !deleted) && c.f.match(req.Filter, dn, attrs) {
			dns = append(dns, dn)
		}
	}
	slices.Sort(dns)
	if p, ok := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok {
		off, _ := strconv.Atoi(string(p.Cookie))
		end := min(off+int(p.PagingSize), len(dns))
		next := ""
		if end < len(dns) {
			next = strconv.Itoa(end)
		}
		dns = dns[off:end]
		resp := ldap.NewControlPaging(0)
		resp.SetCookie([]byte(next))
		res.Controls = append(res.Controls, resp)
	}
	for _, dn := range dns {
		res.Entries = append(res.Entries, ldap.NewEntry(dn, selectAttrs(c.f.tree[dn], req.Attributes)))
	}
	return res, nil
}

// selectAttrs keeps the requested attributes (all for none or *), slicing
// a;range=lo-hi requests the way AD does.
func selectAttrs(attrs map[string][]string, want []string) map[string][]string {
	if len(want) == 0 || slices.Contains(want, "*") {
		return attrs
	}
	out := map[string][]string{}
	for _, w := range want {
		name, rng, ranged := strings.Cut(w, ";range=")
		for k, v := range attrs {
			if !strings.EqualFold(k, name) {
				continue
			}
			if !ranged {
				out[k] = v
				continue
			}
			lo, hi, _ := strings.Cut(rng, "-")
			l, _ := strconv.Atoi(lo)
			h, err := strconv.Atoi(hi)
			if l >= len(v) {
				out[k+";range="+lo+"-*"] = nil
				continue
			}
			if err != nil || h >= len(v)-1 {
				out[fmt.Sprintf("%s;range=%d-*", k, l)] = v[l:]
			} else {
				out[fmt.Sprintf("%s;range=%d-%d", k, l, h)] = v[l : h+1]
			}
		}
	}
	return out
}

func (f *fakeDir) match(filter, dn string, attrs map[string][]string) bool {
	attrs = maps.Clone(attrs)
	attrs["distinguishedName"] = []string{dn}
	p, err := ldap.CompileFilter(filter)
	if err != nil {
		panic(fmt.Sprintf("filter %q: %v", filter, err))
	}
	return f.eval(p, attrs)
}

func values(attrs map[string][]string, name string) []string {
	for k, v := range attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// eval evaluates the filter subset the server sends: and, or, not,
// presence, equality (anr= matches a sAMAccountName or displayName prefix),
// and the bitwise-and and in-chain matching rules.
func (f *fakeDir) eval(p *ber.Packet, attrs map[string][]string) bool {
	switch p.Tag {
	case ldap.FilterAnd:
		for _, c := range p.Children {
			if !f.eval(c, attrs) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		return slices.ContainsFunc(p.Children, func(c *ber.Packet) bool { return f.eval(c, attrs) })
	case ldap.FilterNot:
		return !f.eval(p.Children[0], attrs)
	case ldap.FilterPresent:
		return strings.EqualFold(p.Data.String(), "objectClass") || values(attrs, p.Data.String()) != nil
	case ldap.FilterEqualityMatch:
		name, want := p.Children[0].Data.String(), p.Children[1].Data.String()
		if strings.EqualFold(name, "anr") {
			for _, a := range []string{"sAMAccountName", "displayName"} {
				for _, v := range values(attrs, a) {
					if strings.HasPrefix(strings.ToLower(v), strings.ToLower(want)) {
						return true
					}
				}
			}
			return false
		}
		return slices.ContainsFunc(values(attrs, name), func(v string) bool { return strings.EqualFold(v, want) })
	case ldap.FilterExtensibleMatch:
		var rule, name, want string
		for _, c := range p.Children {
			switch c.Tag {
			case 1:
				rule = c.Data.String()
			case 2:
				name = c.Data.String()
			case 3:
				want = c.Data.String()
			}
		}
		switch rule {
		case "1.2.840.113556.1.4.803":
			w, _ := strconv.Atoi(want)
			return slices.ContainsFunc(values(attrs, name), func(v string) bool { n, _ := strconv.Atoi(v); return n&w == w })
		case "1.2.840.113556.1.4.1941":
			return f.inChain(values(attrs, name), want, 0)
		}
	}
	panic(fmt.Sprintf("fake filter: unsupported tag %d", p.Tag))
}

// inChain reports whether target is in dns or, through memberOf, above them.
func (f *fakeDir) inChain(dns []string, target string, depth int) bool {
	for _, dn := range dns {
		if strings.EqualFold(dn, target) || depth < 10 && f.inChain(f.tree[strings.ToLower(dn)]["memberOf"], target, depth+1) {
			return true
		}
	}
	return false
}
