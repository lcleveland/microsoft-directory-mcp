package ad

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Link is one GPO link of a gPLink value (MS-GPOL 2.2.2).
type Link struct {
	GPO       string `json:"gpo"`
	LinkOrder int    `json:"link_order"` // 1 wins within its container
	Enforced  bool   `json:"enforced"`
	Disabled  bool   `json:"disabled"`
}

// ParseGPLink parses "[LDAP://<GPO DN>;<options>]…" into link order. The
// value lists links last-first, so its final entry is link order 1.
func ParseGPLink(s string) []Link {
	var out []Link
	for _, part := range strings.Split(s, "[") {
		dn, opts, ok := strings.Cut(strings.TrimSuffix(strings.TrimSpace(part), "]"), ";")
		if !ok {
			continue
		}
		if len(dn) > 7 && strings.EqualFold(dn[:7], "LDAP://") {
			dn = dn[7:]
		}
		n, _ := strconv.Atoi(opts)
		out = append(out, Link{GPO: dn, Disabled: n&1 != 0, Enforced: n&2 != 0})
	}
	slices.Reverse(out)
	for i := range out {
		out[i].LinkOrder = i + 1
	}
	return out
}

// FormatGPLink writes links, in link order, as a gPLink value: last-first.
func FormatGPLink(links []Link) string {
	var b strings.Builder
	for _, l := range slices.Backward(links) {
		n := 0
		if l.Disabled {
			n |= 1
		}
		if l.Enforced {
			n |= 2
		}
		fmt.Fprintf(&b, "[LDAP://%s;%d]", l.GPO, n)
	}
	return b.String()
}

// SetLink puts gpo's link at link order order (0: where it is, or last when
// it is new), setting enforced and disabled unless nil, and renumbers.
func SetLink(links []Link, gpo string, order int, enforced, disabled *bool) ([]Link, error) {
	links = slices.Clone(links)
	l := Link{GPO: gpo}
	if i := slices.IndexFunc(links, func(l Link) bool { return strings.EqualFold(l.GPO, gpo) }); i >= 0 {
		l = links[i]
		links = slices.Delete(links, i, i+1)
		order = cmp.Or(order, i+1)
	}
	order = cmp.Or(order, len(links)+1)
	if order < 1 || order > len(links)+1 {
		return nil, fmt.Errorf("link_order %d: want 1 to %d", order, len(links)+1)
	}
	if enforced != nil {
		l.Enforced = *enforced
	}
	if disabled != nil {
		l.Disabled = *disabled
	}
	links = slices.Insert(links, order-1, l)
	for i := range links {
		links[i].LinkOrder = i + 1
	}
	return links, nil
}

// SOM is a container GPOs link to (a domain, OU or site), with its links
// in link order and whether it blocks inheritance (gPOptions 1).
type SOM struct {
	DN    string
	Links []Link
	Block bool
}

// Applied is one link that reaches a container, by precedence (1 wins).
type Applied struct {
	Precedence int    `json:"precedence"`
	GPO        string `json:"gpo"`
	From       string `json:"from"`
	LinkOrder  int    `json:"link_order"`
	Enforced   bool   `json:"enforced"`
}

// Inheritance lists the links reaching the last container of chain (the
// domain or site first, then each OU down to it) by precedence, as GPMC's
// inheritance tab does: enforced links first, the highest container's
// first; then the rest, the nearest container's first; each container's in
// link order. Disabled links never apply, and block inheritance drops every
// unenforced link of the containers above the one blocking.
func Inheritance(chain []SOM) []Applied {
	blocked := 0
	for i, s := range chain {
		if s.Block {
			blocked = i
		}
	}
	var out []Applied
	add := func(i int, enforced bool) {
		for _, l := range chain[i].Links {
			if !l.Disabled && l.Enforced == enforced && (enforced || i >= blocked) {
				out = append(out, Applied{len(out) + 1, l.GPO, chain[i].DN, l.LinkOrder, enforced})
			}
		}
	}
	for i := range chain {
		add(i, true)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		add(i, false)
	}
	return out
}

// PSOContainer is where a domain keeps its PSOs, under its head.
const PSOContainer = "CN=Password Settings Container,CN=System"

func init() {
	// pso-read: PSOs are readable only with rights delegated (Domain Admins
	// by default). The container must be readable, and so must each PSO's
	// settings; a PSO hidden from listing altogether can't be told from none.
	ReadProbes["pso-read"] = func(conn Conn, root *RootDSE) error {
		const missing = "cannot read the Password Settings Container (delegate Read on it and its PSOs; needs domain functional level 2008)"
		base := PSOContainer + "," + root.DefaultNamingContext
		res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)", []string{"objectClass"}, nil))
		if err == nil && (len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("objectClass") == "") {
			return errors.New(missing)
		}
		if err == nil {
			res, err = conn.Search(ldap.NewSearchRequest(base, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
				"(objectClass=msDS-PasswordSettings)", []string{"msDS-PasswordSettingsPrecedence"}, nil))
		}
		switch {
		case ldap.IsErrorAnyOf(err, ldap.LDAPResultNoSuchObject, ldap.LDAPResultInsufficientAccessRights):
			return errors.New(missing)
		case err != nil:
			return nil // undecided: show
		}
		for _, e := range res.Entries {
			if e.GetAttributeValue("msDS-PasswordSettingsPrecedence") == "" {
				return errors.New("PSOs are listed but their settings are unreadable (delegate Read Property on the PSOs)")
			}
		}
		return nil
	}
}
