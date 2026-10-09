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
	"primaryGroupID", "memberOf", "tokenGroups", "msDS-ObjectSoa", "sAMAccountName", "name"}

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
// attrs) and refuses a protected target; then vet checks the entry and
// builds the modify, which is sent once. Nothing is sent when vet errs.
func (c *Client) Modify(ctx context.Context, dn, class string, attrs []string, vet func(*ldap.Entry) (*ldap.ModifyRequest, error)) (Target, error) {
	d, err := c.DomainOf(ctx, dn)
	if err != nil {
		return Target{}, err
	}
	return c.Write(ctx, d, func(conn Conn) error {
		res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, class,
			append(slices.Clone(preRead), attrs...), nil))
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
		err = conn.Modify(req)
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			var names []string
			for _, ch := range req.Changes {
				names = append(names, ch.Modification.Type)
			}
			return fmt.Errorf("%w; the bind account needs write access to %s on %s: delegate those attributes on its OU, not a whole property set",
				err, strings.Join(slices.Compact(names), ", "), dn)
		}
		return err
	})
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
	case isSID && rid < 1000:
		return fmt.Sprintf("a built-in account or group (RID %d)", rid)
	// An account always has its primary group in tokenGroups, so none at
	// all means the bind account can't read it: fail closed.
	case len(tokens) == 0 && (e.GetAttributeValue("primaryGroupID") != "" || len(e.GetAttributeValues("memberOf")) > 0):
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

// rid is the last sub-authority of a binary SID.
func rid(sid []byte) (uint32, bool) {
	s := SIDString(sid)
	i := strings.LastIndexByte(s, '-')
	n, err := strconv.ParseUint(s[i+1:], 10, 32)
	return uint32(n), strings.HasPrefix(s, "S-") && err == nil
}
