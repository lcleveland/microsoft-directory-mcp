package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
)

// field finds a key of a decoded entry in any case.
func field(m map[string]any, name string) (string, any) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return k, v
		}
	}
	return "", nil
}

func links(m map[string]any) []ad.Link {
	_, v := field(m, "gPLink")
	l, _ := v.([]ad.Link)
	return l
}

var (
	adOUs = adKind{class: "(objectClass=organizationalUnit)",
		brief:  []string{"dn", "name", "description", "linkCount"},
		derive: func(m map[string]any) { m["linkCount"] = len(links(m)) },
	}.curated("gPLink", "gPOptions", "managedBy", "whenCreated", "whenChanged")
	// tree's children: the OUs and their links in full.
	adOUTree = adKind{class: adOUs.class, brief: []string{"dn", "name", "description", "gPLink", "gPOptions"}}
	adGPOs   = adKind{class: "(objectClass=groupPolicyContainer)",
		brief: []string{"dn", "displayName", "name", "flags", "versionNumber", "whenChanged"},
		derive: func(m map[string]any) {
			if k, v := field(m, "flags"); k != "" {
				if s, ok := map[any]string{"0": "enabled", "1": "user_settings_disabled", "2": "computer_settings_disabled",
					"3": "all_settings_disabled"}[v]; ok {
					m[k] = s
				}
			}
		},
	}.curated("gPCFileSysPath", "whenCreated")
	adPSOs = adKind{class: "(objectClass=msDS-PasswordSettings)",
		brief: []string{"dn", "name", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
			"msDS-MaximumPasswordAge", "appliesToCount"},
		derive: func(m map[string]any) {
			_, v := field(m, "msDS-PSOAppliesTo")
			l, _ := v.([]any)
			m["appliesToCount"] = len(l)
		},
	}.curated("msDS-MinimumPasswordAge", "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
		"msDS-PasswordReversibleEncryptionEnabled", "msDS-LockoutDuration", "msDS-LockoutObservationWindow",
		"msDS-PSOAppliesTo", "description", "whenChanged")
	// The domain head's password and lockout policy.
	domainPolicy = []string{"minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge", "pwdProperties",
		"lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"}
)

const (
	somClass   = "(|(objectClass=organizationalUnit)(objectClass=domainDNS)(objectClass=site))"
	ouOrDomain = "(|(objectClass=organizationalUnit)(objectClass=domainDNS))"
	drainLimit = 1000
)

// tree lists the OUs one level under id (an OU or domain head), or under
// every domain head.
func (d Deps) tree(ctx context.Context, in adIn) (map[string]any, error) {
	q := ad.Query{Scope: ldap.ScopeSingleLevel}
	if in.ID != "" {
		e, err := d.AD.Get(ctx, in.ID, ouOrDomain, []string{"1.1"})
		if err != nil {
			return nil, err
		}
		q.Base = e.DN
	}
	return d.search(ctx, adOUTree, in, q)
}

// gpoGet is a GPO's get set and, without fields, the places it is linked.
func (d Deps) gpoGet(ctx context.Context, in adIn) (map[string]any, error) {
	out, err := d.get(ctx, adGPOs, in)
	if err != nil || len(in.Fields) > 0 {
		return out, err
	}
	dn, _ := out["dn"].(string)
	rdn, _, _ := strings.Cut(dn, ",")
	_, guid, _ := strings.Cut(rdn, "=")
	f := "(gPLink=*" + ldap.EscapeFilter(guid) + "*)"
	_, _, root, err := d.AD.Root(ctx)
	if err != nil {
		return nil, err
	}
	soms, skipped, err := d.drain(ctx, ad.Query{Filter: f, Attrs: []string{"gPLink"}})
	if err != nil {
		return nil, err
	}
	sites, _, err := d.drain(ctx, ad.Query{Base: "CN=Sites," + root.ConfigurationNamingContext, Filter: f, Attrs: []string{"gPLink"}})
	if err != nil {
		return nil, err
	}
	linked := []map[string]any{}
	for _, m := range append(soms, sites...) {
		for _, l := range links(m) {
			if strings.Contains(strings.ToLower(l.GPO), strings.ToLower(guid)) {
				linked = append(linked, map[string]any{"dn": m["dn"], "link_order": l.LinkOrder, "enforced": l.Enforced, "disabled": l.Disabled})
			}
		}
	}
	out["linked"] = linked
	if len(skipped) > 0 {
		out["_skipped"] = skipped
	}
	return out, nil
}

// drain reads every page of q, refusing more than drainLimit results.
// ponytail: linked isn't paged; page it if a GPO is ever linked in thousands of places.
func (d Deps) drain(ctx context.Context, q ad.Query) ([]map[string]any, []ad.Skipped, error) {
	var (
		out     []map[string]any
		skipped []ad.Skipped
		cursor  string
	)
	for {
		p, err := d.AD.Search(ctx, q, cursor)
		if err != nil {
			return nil, nil, err
		}
		out, skipped = append(out, p.Results...), append(skipped, p.Skipped...)
		if p.NextCursor == "" {
			return out, skipped, nil
		}
		if len(out) >= drainLimit {
			return nil, nil, fmt.Errorf("more than %d results for %s", drainLimit, q.Filter)
		}
		cursor = p.NextCursor
	}
}

// gpoLinks lists the GPOs linked to an OU, domain head or site, and those
// reaching it by inheritance in precedence order. An OU inherits from each
// container above it up to its domain head; a site inherits nothing.
func (d Deps) gpoLinks(ctx context.Context, in adIn) (map[string]any, error) {
	id := in.ID
	if id == "" {
		if in.Domain == "" {
			return nil, errors.New("links needs id (an OU, domain head or site) or domain")
		}
		dom, err := d.AD.Lookup(ctx, in.Domain)
		if err != nil {
			return nil, err
		}
		id = dom.DN
	}
	e, err := d.AD.Get(ctx, id, somClass, []string{"objectClass"})
	if err != nil {
		return nil, err
	}
	chain := []string{e.DN}
	if !slices.ContainsFunc(e.GetAttributeValues("objectClass"), func(c string) bool { return strings.EqualFold(c, "site") }) {
		dom, err := d.AD.DomainOf(ctx, e.DN)
		if err != nil {
			return nil, err
		}
		if chain, err = ancestors(dom.DN, e.DN); err != nil {
			return nil, err
		}
	}
	read, err := d.AD.ReadMany(ctx, chain, []string{"gPLink", "gPOptions"})
	if err != nil {
		return nil, err
	}
	soms := make([]ad.SOM, len(read))
	for i, m := range read {
		_, opts := field(m, "gPOptions")
		soms[i] = ad.SOM{DN: chain[i], Links: links(m), Block: opts == "1"}
	}
	target := soms[len(soms)-1]
	inherited := ad.Inheritance(soms)

	// Name each GPO.
	var gpos []string
	for _, l := range target.Links {
		gpos = append(gpos, l.GPO)
	}
	for _, a := range inherited {
		gpos = append(gpos, a.GPO)
	}
	slices.Sort(gpos)
	gpos = slices.Compact(gpos)
	named, err := d.AD.ReadMany(ctx, gpos, []string{"displayName"})
	if err != nil {
		return nil, err
	}
	names := map[string]any{}
	for i, m := range named {
		names[strings.ToLower(gpos[i])] = m["displayName"]
	}
	own, applied := []map[string]any{}, []map[string]any{}
	for _, l := range target.Links {
		own = append(own, map[string]any{"gpo": l.GPO, "displayName": names[strings.ToLower(l.GPO)],
			"link_order": l.LinkOrder, "enforced": l.Enforced, "disabled": l.Disabled})
	}
	for _, a := range inherited {
		applied = append(applied, map[string]any{"precedence": a.Precedence, "gpo": a.GPO, "displayName": names[strings.ToLower(a.GPO)],
			"from": a.From, "link_order": a.LinkOrder, "enforced": a.Enforced})
	}
	return map[string]any{"dn": e.DN, "block_inheritance": target.Block, "links": own, "inheritance": applied}, nil
}

// ancestors lists dn's containers from top (a domain head) down to dn itself.
func ancestors(top, dn string) ([]string, error) {
	t, err := ldap.ParseDN(top)
	if err != nil {
		return nil, err
	}
	p, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, err
	}
	if !t.EqualFold(p) && !t.AncestorOfFold(p) {
		return nil, fmt.Errorf("%s is not under %s", dn, top)
	}
	// Each RDN starts after an unescaped comma; keep dn's own spelling.
	starts, esc := []int{0}, false
	for i, r := range dn {
		switch {
		case esc:
			esc = false
		case r == '\\':
			esc = true
		case r == ',':
			starts = append(starts, i+1)
		}
	}
	if len(starts) != len(p.RDNs) {
		return nil, fmt.Errorf("%s: unsupported DN quoting", dn)
	}
	var out []string
	for n := len(t.RDNs); n <= len(p.RDNs); n++ {
		out = append(out, strings.TrimSpace(dn[starts[len(p.RDNs)-n]:]))
	}
	return out, nil
}

// domainDefault reads the domain head's policy of each domain, or only domain.
func (d Deps) domainDefault(ctx context.Context, domain string) ([]map[string]any, []ad.Skipped, error) {
	out, skipped, err := ad.FanOut(ctx, d.AD, domain, func(conn ad.Conn, dom ad.Domain) ([]map[string]any, error) {
		res, err := conn.Search(ldap.NewSearchRequest(dom.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=domainDNS)", domainPolicy, nil))
		if err != nil {
			return nil, err
		}
		if len(res.Entries) != 1 {
			return nil, errors.New(dom.DN + ": domain head not found")
		}
		m := ad.Decode(res.Entries[0], domainPolicy)
		m["domain"] = dom.DNS
		return []map[string]any{m}, nil
	})
	slices.SortFunc(out, func(a, b map[string]any) int { return cmp.Compare(a["domain"].(string), b["domain"].(string)) })
	return out, skipped, err
}

// resultantPolicy is the PSO that applies to a user, else its domain's default.
func (d Deps) resultantPolicy(ctx context.Context, in adIn) (map[string]any, error) {
	if in.ID == "" {
		return nil, errors.New("resultant_policy needs id")
	}
	e, err := d.AD.Get(ctx, in.ID, adUsers.class, []string{"msDS-ResultantPSO"})
	if err != nil {
		return nil, err
	}
	if pso := e.GetAttributeValue("msDS-ResultantPSO"); pso != "" {
		p, err := d.get(ctx, adPSOs, adIn{ID: pso})
		return map[string]any{"user": e.DN, "source": "pso", "policy": p}, err
	}
	dom, err := d.AD.DomainOf(ctx, e.DN)
	if err != nil {
		return nil, err
	}
	p, _, err := d.domainDefault(ctx, dom.DNS)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("%s: domain unreachable", dom.DNS)
	}
	return map[string]any{"user": e.DN, "source": "domain_default", "policy": p[0]}, nil
}

// ad_ou, ad_gpo and ad_policy, placed in the roster by ad_read.go.
var (
	adOUTool = adReadTool("ad_ou", "identity", "Active Directory OUs",
		"Organizational units of the forest. search: list OUs as briefs (dn, name, description, linkCount: how many "+
			"GPOs are linked). get: one OU by DN or objectGUID, with gPLink (each linked GPO's DN, link_order, enforced "+
			"and disabled), gPOptions (1 blocks inheritance) and managedBy. tree: the OUs one level under id (an OU or "+
			"domain head; without id, under each domain head, or only domain's) with their gPLink and gPOptions.", adOUs,
		adExtra{Action{Name: "tree"}, Deps.tree})
	adGPOTool = adReadTool("ad_gpo", "policy", "Active Directory GPOs",
		"Group Policy objects (groupPolicyContainer) and their links; settings are never read. search: list GPOs as "+
			"briefs (dn, displayName, name: the GPO's GUID, flags as status, versionNumber, whenChanged). get: one GPO by "+
			"DN or its GUID, with gPCFileSysPath and linked: every OU, domain head and site linking it. links: for an OU, "+
			"domain head or site (id, or domain for a domain head), its own links in link order (enforced, disabled), "+
			"block_inheritance, and inheritance: every link reaching it by precedence (1 wins), as GPMC's Group Policy "+
			"Inheritance tab lists them: enforced links first, then the nearest container's.", adGPOs,
		adExtra{Action{Name: "get"}, Deps.gpoGet}, adExtra{Action{Name: "links"}, Deps.gpoLinks})
	adPolicyTool = Tool{Name: "ad_policy", Group: "policy", Actions: []Action{{Name: "domain_default"}, {Name: "psos", ADProbe: "pso-read"}},
		add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
			addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Active Directory password policy", Annotations: readOnly,
				Description: "Password and lockout policy. domain_default: each domain's default policy from its head " +
					"(or only domain's): minPwdLength, pwdHistoryLength, maxPwdAge, minPwdAge, pwdProperties flags, " +
					"lockoutThreshold, lockoutDuration and lockOutObservationWindow; ages and durations are ISO 8601, " +
					"null for never (a null lockoutDuration: until an admin unlocks). psos: without id, list the fine-grained " +
					"password policies (PSOs) of each domain as briefs (dn, name, precedence: lower wins, minimum length, " +
					"lockout threshold, maximum age, appliesToCount); with id (DN or objectGUID), one PSO with every " +
					"setting and msDS-PSOAppliesTo (the users and groups it applies to). ad_user resultant_policy says which " +
					"applies to a user.\n\n" + adSearchDoc},
				visible, func(ctx context.Context, _ *mcp.CallToolRequest, in adIn) (*mcp.CallToolResult, map[string]any, error) {
					if in.Action == "domain_default" {
						res, skipped, err := d.domainDefault(ctx, in.Domain)
						if err != nil {
							return nil, nil, err
						}
						return nil, obj(ad.Page{Results: append([]map[string]any{}, res...), Skipped: skipped}), nil
					}
					if in.ID != "" {
						out, err := d.get(ctx, adPSOs, in)
						return nil, out, err
					}
					out, err := d.search(ctx, adPSOs, in, ad.Query{Under: ad.PSOContainer, Scope: ldap.ScopeSingleLevel})
					return nil, out, err
				})
		}}
)
