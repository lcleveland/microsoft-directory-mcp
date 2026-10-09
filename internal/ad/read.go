package ad

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ErrNoMatch is wrapped by Resolve and Get when no object matches.
var ErrNoMatch = errors.New("no match")

var guidRE = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`)

// Resolve turns an identifier into the DN of an object matching class (an
// LDAP filter). The identifier is detected: a DN (has =) is returned as is;
// a SID (S-1-), GUID (objectGUID, or a GPO's name) or UPN (has @) is found on the GC; anything else is a
// sAMAccountName, optionally DOMAIN\sam, searched domain by domain.
func (c *Client) Resolve(ctx context.Context, id, class string) (string, error) {
	var filter string
	switch {
	case strings.Contains(id, "="):
		return id, nil
	case strings.HasPrefix(strings.ToUpper(id), "S-1-"):
		b, err := SIDBytes(id)
		if err != nil {
			return "", err
		}
		filter = "(objectSid=" + escapeBytes(b) + ")"
	case guidRE.MatchString(id):
		b, err := GUIDBytes(id)
		if err != nil {
			return "", err
		}
		// A GPO is named by its GUID, which isn't its objectGUID.
		filter = "(|(objectGUID=" + escapeBytes(b) + ")(cn={" + strings.Trim(id, "{}") + "}))"
	case strings.Contains(id, "@"):
		filter = "(userPrincipalName=" + ldap.EscapeFilter(id) + ")"
	default:
		domain, sam, ok := strings.Cut(id, `\`)
		if !ok {
			domain, sam = "", id
		}
		dns, _, err := FanOut(ctx, c, domain, func(conn Conn, d Domain) ([]string, error) {
			return searchDNs(conn, d.DN, "(&"+class+"(sAMAccountName="+ldap.EscapeFilter(sam)+"))")
		})
		if err != nil {
			return "", err
		}
		return one(id, dns)
	}
	gc, _, err := c.GC(ctx)
	if err != nil {
		return "", fmt.Errorf("global catalog: %w", err)
	}
	dns, err := searchDNs(gc, "", "(&"+class+filter+")")
	if err != nil {
		return "", err
	}
	return one(id, dns)
}

// searchDNs returns the DNs under base matching filter, at most a few.
func searchDNs(conn Conn, base, filter string) ([]string, error) {
	res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10, 0, false,
		filter, []string{"1.1"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, err
	}
	var out []string
	if res != nil {
		for _, e := range res.Entries {
			out = append(out, e.DN)
		}
	}
	return out, nil
}

func one(id string, dns []string) (string, error) {
	switch len(dns) {
	case 0:
		return "", fmt.Errorf("%q: %w for this tool (a DN, SID, GUID, UPN, sAMAccountName or DOMAIN\\sam)", id, ErrNoMatch)
	case 1:
		return dns[0], nil
	}
	return "", fmt.Errorf("%q matches %d objects; pass one of these DNs as id: %s", id, len(dns), strings.Join(dns, "; "))
}

// Get resolves id and reads attrs of it, if it matches class, from a DC of
// the domain that owns it.
func (c *Client) Get(ctx context.Context, id, class string, attrs []string) (*ldap.Entry, error) {
	dn, err := c.Resolve(ctx, id, class)
	if err != nil {
		return nil, err
	}
	d, err := c.DomainOf(ctx, dn)
	if err != nil {
		return nil, err
	}
	conn, _, err := c.Conn(ctx, d)
	if err != nil {
		return nil, err
	}
	res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, class, attrs, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || err == nil && len(res.Entries) == 0 {
		return nil, fmt.Errorf("%q: %w for this tool", id, ErrNoMatch)
	}
	if err != nil {
		return nil, err
	}
	return res.Entries[0], nil
}

// Values reads up to n values of a multi-valued attribute of dn from offset
// on, by range retrieval. next is the offset after them, or -1 at the end.
func (c *Client) Values(ctx context.Context, dn, attr string, offset, n int) (vals []string, next int, err error) {
	d, err := c.DomainOf(ctx, dn)
	if err != nil {
		return nil, 0, err
	}
	conn, _, err := c.Conn(ctx, d)
	if err != nil {
		return nil, 0, err
	}
	next = offset
	for len(vals) < n {
		rng := fmt.Sprintf("%s;range=%d-%d", attr, next, next+n-len(vals)-1)
		res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)", []string{rng}, nil))
		if err != nil {
			return nil, 0, err
		}
		if len(res.Entries) != 1 {
			return nil, 0, errors.New(dn + ": not found")
		}
		var got *ldap.EntryAttribute
		for _, a := range res.Entries[0].Attributes {
			if name, _, _ := strings.Cut(a.Name, ";"); strings.EqualFold(name, attr) {
				got = a
			}
		}
		if got == nil { // no values at all, or none from offset on
			return vals, -1, nil
		}
		vals = append(vals, got.Values...)
		next += len(got.Values)
		if strings.HasSuffix(got.Name, "-*") || len(got.Values) == 0 {
			return vals, -1, nil
		}
	}
	return vals, next, nil
}

// ReadMany reads attrs of each DN, in order, decoded, with one search per
// owning domain. A DN it can't read comes back as {dn} alone.
func (c *Client) ReadMany(ctx context.Context, dns []string, attrs []string) ([]map[string]any, error) {
	byDomain := map[string][]string{}
	doms := map[string]Domain{}
	for _, dn := range dns {
		if d, err := c.DomainOf(ctx, dn); err == nil {
			byDomain[d.DN] = append(byDomain[d.DN], dn)
			doms[d.DN] = d
		}
	}
	found := map[string]map[string]any{}
	for key, list := range byDomain {
		conn, _, err := c.Conn(ctx, doms[key])
		if err != nil {
			continue // unreachable: those members show as DNs
		}
		f := "(|"
		for _, dn := range list {
			f += "(distinguishedName=" + ldap.EscapeFilter(dn) + ")"
		}
		res, err := conn.Search(ldap.NewSearchRequest(key, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			f+")", attrs, nil))
		if err != nil && !unreachable(err) {
			return nil, fmt.Errorf("%s: %w", doms[key].DNS, err)
		}
		if res != nil {
			for _, e := range res.Entries {
				found[strings.ToLower(e.DN)] = Decode(e, attrs)
			}
		}
	}
	out := make([]map[string]any, len(dns))
	for i, dn := range dns {
		if out[i] = found[strings.ToLower(dn)]; out[i] == nil {
			out[i] = map[string]any{"dn": dn}
		}
	}
	return out, nil
}
