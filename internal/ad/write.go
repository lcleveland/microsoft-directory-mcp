package ad

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ErrProtected is wrapped by Modify when the target is a protected target.
var ErrProtected = errors.New("protected target: the server never writes it, whatever capabilities are enabled")

// preRead are the attributes Modify reads of a target before writing it:
// what the protected check needs, its names (for confirm) and its source of
// authority.
var preRead = []string{"objectClass", "objectSid", "adminCount", "isCriticalSystemObject", "userAccountControl",
	"primaryGroupID", "memberOf", "tokenGroups", "msDS-ObjectSoa", "sAMAccountName", "name", "isDeleted"}

// The protected groups by RID (Appendix C of the AD security best practices):
// their members, direct or nested, are protected targets.
var (
	// S-1-5-32-…: Administrators, Account, Server, Print and Backup Operators, Replicator.
	builtinProtected = []uint32{544, 548, 549, 550, 551, 552}
	// Of a domain: Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, Read-only Domain
	// Controllers, Key Admins, Enterprise Key Admins (518, 519 and 527 exist only in the forest root domain).
	domainProtected = []uint32{512, 516, 518, 519, 521, 526, 527}
)

// Modify writes the one object dn, if it matches class, on its domain's
// PDC emulator (see Write). There it first reads the target (preRead plus
// attrs; deleted objects too, for a restore) and refuses a protected
// target; then vet checks the entry and builds the request, a modify,
// delete or modify DN of it, which is sent once. Nothing is sent when vet
// errs. sending, if not nil, is called once nothing is left to refuse,
// just before the request is sent.
func (c *Client) Modify(ctx context.Context, dn, class string, attrs []string, vet func(*ldap.Entry) (any, error), sending func()) (Target, error) {
	d, err := c.DomainOf(ctx, dn)
	if err != nil {
		return Target{}, err
	}
	return c.Write(ctx, d, func(conn Conn) error {
		res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, class,
			append(slices.Clone(preRead), attrs...), []ldap.Control{ldap.NewControlMicrosoftShowDeleted()}))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || err == nil && len(res.Entries) == 0 {
			return fmt.Errorf("%q: %w for this tool", dn, ErrNoMatch)
		}
		if err != nil {
			return err
		}
		e := res.Entries[0]
		if why := protected(e); why != "" {
			return fmt.Errorf("%s: %w: %s", dn, ErrProtected, why)
		}
		req, err := vet(e)
		if err != nil {
			return err
		}
		// A deleted object is written only by a modify that itself shows deleted objects: a restore.
		if m, ok := req.(*ldap.ModifyRequest); strings.EqualFold(e.GetAttributeValue("isDeleted"), "TRUE") &&
			(!ok || ldap.FindControl(m.Controls, ldap.ControlTypeMicrosoftShowDeleted) == nil) {
			return fmt.Errorf("%s is deleted: only ad_object restore writes it", e.DN)
		}
		if r, ok := req.(*ldap.ModifyDNRequest); ok && r.NewSuperior != "" {
			to, err := c.DomainOf(ctx, r.NewSuperior)
			if err != nil {
				return err
			}
			if to.DN != d.DN {
				return fmt.Errorf("%s is in %s and %s in %s: cross-domain moves are never made", e.DN, d.DNS, r.NewSuperior, to.DNS)
			}
		}
		if sending != nil {
			sending()
		}
		return send(conn, req)
	})
}

// Add adds the object req names on the PDC emulator of its domain, once.
func (c *Client) Add(ctx context.Context, req *ldap.AddRequest) (Target, error) {
	d, err := c.DomainOf(ctx, req.DN)
	if err != nil {
		return Target{}, err
	}
	return c.Write(ctx, d, func(conn Conn) error { return send(conn, req) })
}

// send sends one write request, saying what the bind account lacks when
// it is refused for access.
func send(conn Conn, req any) error {
	var err error
	need := ""
	switch r := req.(type) {
	case *ldap.ModifyRequest:
		var names []string
		for _, ch := range r.Changes {
			names = append(names, ch.Modification.Type)
		}
		err, need = conn.Modify(r), "write access to "+strings.Join(slices.Compact(names), ", ")+" on "+r.DN+
			": delegate those attributes on its OU, not a whole property set"
	case *ldap.AddRequest:
		err, need = conn.Add(r), "Create Child for this class on the parent of "+r.DN
	case *ldap.DelRequest:
		err, need = conn.Del(r), "Delete on "+r.DN+" (or Delete Child on its parent)"
	case *ldap.ModifyDNRequest:
		err, need = conn.ModifyDN(r), "Delete Child on the parent of "+r.DN+", Create Child on the new parent, and write access to its name"
	default:
		panic(fmt.Sprintf("ad: not a write request: %T", req))
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		return fmt.Errorf("%w; the bind account needs %s", err, need)
	}
	return err
}

// protected says why the pre-read entry e is a protected target, or ""
// when it is not. Nested membership comes from tokenGroups, the SIDs of
// every security group e is in, transitively, primary group and
// forest-wide universal groups included, as its DC computes them.
func protected(e *ldap.Entry) string {
	uac, _ := strconv.ParseUint(e.GetAttributeValue("userAccountControl"), 10, 32)
	tokens := e.GetRawAttributeValues("tokenGroups")
	switch rid, isSID := rid(e.GetRawAttributeValue("objectSid")); {
	case e.GetAttributeValue("adminCount") == "1":
		return "adminCount=1 (it is, or was, in a protected group)"
	case strings.EqualFold(e.GetAttributeValue("isCriticalSystemObject"), "TRUE"):
		return "isCriticalSystemObject"
	case uac&0x2000 != 0:
		return "a domain controller (SERVER_TRUST_ACCOUNT)"
	case dcOU(e.DN):
		return "the Domain Controllers OU: policy linked there reaches every domain controller"
	case isSID && rid < 1000:
		return fmt.Sprintf("a built-in account or group (RID %d)", rid)
	// An account always has its primary group in tokenGroups, so none at
	// all means the bind account can't read it: fail closed. A deleted
	// object has none to read: its links are hidden until it is restored,
	// and adminCount stays to say it was in a protected group.
	case len(tokens) == 0 && !strings.EqualFold(e.GetAttributeValue("isDeleted"), "TRUE") && (e.GetAttributeValue("primaryGroupID") != "" || len(e.GetAttributeValues("memberOf")) > 0):
		return "its tokenGroups can't be read, so its group memberships can't be checked: add the bind account to the " +
			"Windows Authorization Access Group of its domain"
	}
	for _, t := range tokens {
		s := SIDString(t)
		r, _ := rid(t)
		if strings.HasPrefix(s, "S-1-5-32-") && slices.Contains(builtinProtected, r) ||
			strings.HasPrefix(s, "S-1-5-21-") && slices.Contains(domainProtected, r) {
			return "a member, direct or nested, of a protected group (" + s + ")"
		}
	}
	return ""
}

// dcOU reports whether dn is a domain's Domain Controllers OU, which can't
// be renamed or moved.
func dcOU(dn string) bool {
	p, err := ldap.ParseDN(dn)
	if err != nil || len(p.RDNs) < 2 || len(p.RDNs[0].Attributes) != 1 {
		return false
	}
	if a := p.RDNs[0].Attributes[0]; !strings.EqualFold(a.Type, "OU") || !strings.EqualFold(a.Value, "Domain Controllers") {
		return false
	}
	return !slices.ContainsFunc(p.RDNs[1:], func(r *ldap.RelativeDN) bool { return !strings.EqualFold(r.Attributes[0].Type, "DC") })
}

// rid is the last sub-authority of a binary SID.
func rid(sid []byte) (uint32, bool) {
	s := SIDString(sid)
	i := strings.LastIndexByte(s, '-')
	n, err := strconv.ParseUint(s[i+1:], 10, 32)
	return uint32(n), strings.HasPrefix(s, "S-") && err == nil
}

// Protected reads dn from a DC of its domain and says why it is a protected
// target, or "" when it is not: for the other objects a write names, such
// as the members a membership write adds or removes.
func (c *Client) Protected(ctx context.Context, dn string) (string, error) {
	_, _, e, err := c.preRead(ctx, dn)
	if err != nil {
		return "", err
	}
	return protected(e), nil
}

// preRead reads dn's preRead attributes from a DC of its domain.
func (c *Client) preRead(ctx context.Context, dn string) (Domain, Conn, *ldap.Entry, error) {
	d, err := c.DomainOf(ctx, dn)
	if err != nil {
		return d, nil, nil, err
	}
	conn, _, err := c.Conn(ctx, d)
	if err != nil {
		return d, nil, nil, err
	}
	res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", preRead, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || err == nil && len(res.Entries) == 0 {
		return d, nil, nil, fmt.Errorf("%q: %w", dn, ErrNoMatch)
	}
	if err != nil {
		return d, nil, nil, err
	}
	return d, conn, res.Entries[0], nil
}

// Reaches reads dn, a user or group, and says why a policy applied to it
// reaches a protected target, or "" when none does: it is one, or it is a
// group with one among its members, direct or nested. A member counts when
// it has adminCount, is a critical system object (every built-in principal
// is) or a domain controller, or is in a protected group of the domain,
// which also catches one added since SDProp last set its adminCount.
// ponytail: members by primary group only, and those in another domain's
// protected groups (Enterprise Admins), count through adminCount alone.
func (c *Client) Reaches(ctx context.Context, dn string) (string, error) {
	d, conn, e, err := c.preRead(ctx, dn)
	if err != nil {
		return "", err
	}
	if why := protected(e); why != "" || !slices.ContainsFunc(e.GetAttributeValues("objectClass"), func(c string) bool { return strings.EqualFold(c, "group") }) {
		return why, nil
	}
	head, err := conn.Search(ldap.NewSearchRequest(d.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"objectSid"}, nil))
	if err != nil {
		return "", err
	}
	domSID := ""
	if len(head.Entries) == 1 {
		domSID = SIDString(head.Entries[0].GetRawAttributeValue("objectSid"))
	}
	if !strings.HasPrefix(domSID, "S-1-5-21-") {
		return "", fmt.Errorf("%s: can't read the domain's objectSid, so its protected groups can't be found", d.DN)
	}
	f := "(|"
	for _, r := range builtinProtected {
		f += sidFilter(fmt.Sprintf("S-1-5-32-%d", r))
	}
	for _, r := range domainProtected {
		f += sidFilter(fmt.Sprintf("%s-%d", domSID, r))
	}
	groups, err := conn.Search(ldap.NewSearchRequest(d.DN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, f+")", []string{"1.1"}, nil))
	if err != nil {
		return "", err
	}
	const inChain = "(memberOf:1.2.840.113556.1.4.1941:="
	f = "(&" + inChain + ldap.EscapeFilter(e.DN) + ")(|(adminCount=1)(isCriticalSystemObject=TRUE)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
	for _, g := range groups.Entries {
		f += inChain + ldap.EscapeFilter(g.DN) + ")"
	}
	hits, err := searchDNs(conn, d.DN, f+"))")
	if err != nil || len(hits) == 0 {
		return "", err
	}
	return "its member " + hits[0] + " is a protected target, or is in a protected group", nil
}

// sidFilter matches the object whose objectSid is s.
func sidFilter(s string) string {
	b, _ := SIDBytes(s)
	return "(objectSid=" + escapeBytes(b) + ")"
}
