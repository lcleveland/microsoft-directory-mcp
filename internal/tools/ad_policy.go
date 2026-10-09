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

func links(m map[string]any) []ad.Link {
	_, v := ad.Field(m, "gPLink")
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
			if k, v := ad.Field(m, "flags"); k != "" {
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
			_, v := ad.Field(m, "msDS-PSOAppliesTo")
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
			d.AD.Release(p.NextCursor)
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
		_, opts := ad.Field(m, "gPOptions")
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
		adExtra{Action: Action{Name: "tree"}, run: Deps.tree})
	adGPOTool = adReadTool("ad_gpo", "policy", "Active Directory GPOs",
		"Group Policy objects (groupPolicyContainer) and their links; settings are never read. search: list GPOs as "+
			"briefs (dn, displayName, name: the GPO's GUID, flags as status, versionNumber, whenChanged). get: one GPO by "+
			"DN or its GUID, with gPCFileSysPath and linked: every OU, domain head and site linking it. links: for an OU, "+
			"domain head or site (id, or domain for a domain head), its own links in link order (enforced, disabled), "+
			"block_inheritance, and inheritance: every link reaching it by precedence (1 wins), as GPMC's Group Policy "+
			"Inheritance tab lists them: enforced links first, then the nearest container's.", adGPOs,
		adExtra{Action: Action{Name: "get"}, run: Deps.gpoGet}, adExtra{Action: Action{Name: "links"}, run: Deps.gpoLinks},
		adExtra{Action: Action{Name: "link", Capabilities: []string{"ad-gpo-links"}}, run: Deps.gpoLink, doc: gpoWriteDoc},
		adExtra{Action: Action{Name: "unlink", Capabilities: []string{"ad-gpo-links"}}, run: Deps.gpoLink},
		adExtra{Action: Action{Name: "block_inheritance", Capabilities: []string{"ad-gpo-links"}}, run: Deps.blockInheritance})
	adPolicyTool = Tool{Name: "ad_policy", Group: "policy", Actions: []Action{{Name: "domain_default"}, {Name: "psos", ADProbe: "pso-read"},
		{Name: "create", ADProbe: "pso-read", Capabilities: []string{"ad-password-policy"}},
		{Name: "edit", ADProbe: "pso-read", Capabilities: []string{"ad-password-policy"}},
		{Name: "apply", ADProbe: "pso-read", Capabilities: []string{"ad-password-policy"}},
		{Name: "unapply", ADProbe: "pso-read", Capabilities: []string{"ad-password-policy"}}},
		add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
			doc := ""
			if slices.Contains(visible, "apply") {
				doc = psoWriteDoc
			}
			addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Active Directory password policy", Annotations: readOnly,
				Description: "Password and lockout policy. domain_default: each domain's default policy from its head " +
					"(or only domain's): minPwdLength, pwdHistoryLength, maxPwdAge, minPwdAge, pwdProperties flags, " +
					"lockoutThreshold, lockoutDuration and lockOutObservationWindow; ages and durations are ISO 8601, " +
					"null for never (a null lockoutDuration: until an admin unlocks). psos: without id, list the fine-grained " +
					"password policies (PSOs) of each domain as briefs (dn, name, precedence: lower wins, minimum length, " +
					"lockout threshold, maximum age, appliesToCount); with id (DN or objectGUID), one PSO with every " +
					"setting and msDS-PSOAppliesTo (the users and groups it applies to). ad_user resultant_policy says which " +
					"applies to a user.\n\n" + adSearchDoc + doc},
				visible, func(ctx context.Context, _ *mcp.CallToolRequest, pin adPolicyIn) (*mcp.CallToolResult, map[string]any, error) {
					in := pin.read()
					switch in.Action {
					case "create":
						out, err := d.psoCreate(ctx, pin)
						return nil, out, err
					case "edit", "apply", "unapply":
						out, err := d.psoWrite(ctx, pin)
						return nil, out, err
					}
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

// gpoWriteDoc describes ad_gpo's writes when they show.
const gpoWriteDoc = "\n\nWrites (the ad-gpo-links capability), on one OU, domain head or site by id, with a reason; GPOs " +
	"themselves are never created or changed. link: links gpo to id, or changes its link there: link_order (1 wins; default " +
	"where it is, or last), enforced and enabled. unlink: removes gpo's link from id. block_inheritance: block=true (the " +
	"default) stops id inheriting unenforced links from above; block=false inherits again. Each is one compare-and-swap of " +
	"gPLink (or gPOptions) on the PDC emulator, so it fails rather than overwrites a change made since the read: read and " +
	"retry. The Domain Controllers OU is refused. The reply's links are id's links after the change; ad_gpo links shows " +
	"what reaches it."

// psoWriteDoc describes ad_policy's writes when they show.
const psoWriteDoc = "\n\nWrites (the ad-password-policy capability), with a reason. create: a PSO named name in domain's " +
	"Password Settings Container (default the forest root domain), with every setting in attributes; it applies to nobody " +
	"until apply. edit: replaces settings of one PSO by id. Settings are LDAP values: msDS-PasswordSettingsPrecedence (lower " +
	"wins), msDS-MinimumPasswordLength, msDS-PasswordHistoryLength and msDS-LockoutThreshold as numbers; " +
	"msDS-PasswordComplexityEnabled and msDS-PasswordReversibleEncryptionEnabled as TRUE or FALSE; " +
	"msDS-MinimumPasswordAge, msDS-MaximumPasswordAge, msDS-LockoutObservationWindow and msDS-LockoutDuration as negative " +
	"100-nanosecond intervals (-864000000000 is one day, -18000000000 thirty minutes; -9223372036854775808 is never). " +
	"apply, unapply: adds or removes up to 20 users or global security groups (applies_to) on one PSO by id; one already " +
	"there (or already gone) is no error. Protected targets are refused: applying to a protected user or group, or to a group " +
	"with one among its members (direct or nested), and any write to a PSO that already applies to one."

// psoClass is a PSO's objectClass.
const psoClass = "msDS-PasswordSettings"

// psoSettings are the settings ad_policy create and edit set: every one a
// PSO must have, and nothing else.
var psoSettings = []string{"msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
	"msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled", "msDS-MinimumPasswordAge",
	"msDS-MaximumPasswordAge", "msDS-LockoutThreshold", "msDS-LockoutObservationWindow", "msDS-LockoutDuration"}

func init() {
	for _, a := range psoSettings {
		adOps = append(adOps, adOp{"modify", a, "ad-password-policy", "ad_policy edit"})
	}
}

// gpoLink is ad_gpo link or unlink (ad-gpo-links): one GPO's link on an
// OU, domain head or site (id), set or removed by a compare-and-swap of
// its gPLink. The Domain Controllers OU is a protected target.
func (d Deps) gpoLink(ctx context.Context, in adIn) (map[string]any, error) {
	if in.GPO == "" {
		return nil, errors.New(in.Action + " needs gpo (a GPO by DN or GUID) and id (the OU, domain head or site)")
	}
	var after []ad.Link
	out, err := d.adWrite(ctx, adWrite{tool: "ad_gpo", action: in.Action, id: in.ID, class: somClass, in: in.writeIn, attrs: []string{"gPLink"},
		changes: func(e *ldap.Entry) ([]ldap.Change, error) {
			g, err := adGet(d.AD, ctx, in.GPO, adGPOs.class, []string{"1.1"})
			// A deleted GPO's link stays behind: unlink takes it by DN.
			if errors.Is(err, ad.ErrNoMatch) && in.Action == "unlink" && strings.Contains(in.GPO, "=") {
				g, err = ldap.NewEntry(in.GPO, nil), nil
			}
			if err != nil {
				return nil, fmt.Errorf("gpo %w", err)
			}
			old := e.GetAttributeValue("gPLink")
			links := ad.ParseGPLink(old)
			if in.Action == "unlink" {
				n := len(links)
				if links = slices.DeleteFunc(links, func(l ad.Link) bool { return strings.EqualFold(l.GPO, g.DN) }); len(links) == n {
					return nil, fmt.Errorf("%s is not linked to %s", g.DN, e.DN)
				}
			} else {
				var disabled *bool
				if in.Enabled != nil {
					disabled = new(!*in.Enabled)
				}
				if links, err = ad.SetLink(links, g.DN, in.LinkOrder, in.Enforced, disabled); err != nil {
					return nil, err
				}
			}
			after = ad.ParseGPLink(ad.FormatGPLink(links))
			return swap("gPLink", old, ad.FormatGPLink(links)), nil
		}})
	if err != nil {
		return nil, err
	}
	out["links"] = append([]ad.Link{}, after...) // [] rather than null when none is left
	return out, nil
}

// blockInheritance is ad_gpo block_inheritance (ad-gpo-links): gPOptions
// on an OU or domain head, 1 to block, 0 to inherit, as a compare-and-swap.
func (d Deps) blockInheritance(ctx context.Context, in adIn) (map[string]any, error) {
	v := "1"
	if in.Block != nil && !*in.Block {
		v = "0"
	}
	return d.adWrite(ctx, adWrite{tool: "ad_gpo", action: "block_inheritance", id: in.ID, class: ouOrDomain, in: in.writeIn,
		attrs: []string{"gPOptions"}, changes: func(e *ldap.Entry) ([]ldap.Change, error) {
			// No gPOptions at all inherits, as 0 does.
			if old := e.GetAttributeValue("gPOptions"); cmp.Or(old, "0") != v {
				return swap("gPOptions", old, v), nil
			}
			return nil, fmt.Errorf("%s already has gPOptions %s", e.DN, v)
		}})
}

// adPolicyIn is ad_policy's input.
type adPolicyIn struct {
	ActionParam
	ID     string   `json:"id,omitempty" jsonschema:"psos, edit, apply, unapply: a PSO by DN or objectGUID"`
	Query  string   `json:"query,omitempty" jsonschema:"psos: name lookup by ambiguous name resolution (prefix match)"`
	Filter string   `json:"filter,omitempty" jsonschema:"psos: raw LDAP filter, ANDed with the object class; read the ad://guide/ldap-filter resource first"`
	Domain string   `json:"domain,omitempty" jsonschema:"domain_default, psos: only this domain (DNS or NetBIOS name) instead of every domain; create: the domain to create the PSO in, default the forest root domain"`
	Fields []string `json:"fields,omitempty" jsonschema:"LDAP attribute names to return instead of the default set"`
	Cursor string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call with the same arguments, unchanged"`
	writeIn
	Name       string            `json:"name,omitempty" jsonschema:"writes, create: the PSO's name (its cn)"`
	Attributes map[string]string `json:"attributes,omitempty" jsonschema:"writes, create, edit: PSO settings by LDAP name (msDS-*), as LDAP values; create needs every one"`
	AppliesTo  []string          `json:"applies_to,omitempty" jsonschema:"writes, apply, unapply: up to 20 users or global security groups (a PSO ignores other groups) by id (a DN, SID, GUID, UPN, sAMAccountName or DOMAIN\\sam)"`
}

func (in adPolicyIn) read() adIn {
	return adIn{ActionParam: in.ActionParam, ID: in.ID, Query: in.Query, Filter: in.Filter, Domain: in.Domain, Fields: in.Fields, Cursor: in.Cursor}
}

// psoCreate is ad_policy create (ad-password-policy): one PSO, applying to
// nobody until apply, in a domain's Password Settings Container.
func (d Deps) psoCreate(ctx context.Context, in adPolicyIn) (map[string]any, error) {
	name := in.Domain
	if name == "" && d.Config.AD != nil {
		name = d.Config.AD.Forest
	}
	dom, err := d.AD.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	return d.create(ctx, "ad_policy", psoClass, adIn{Name: in.Name, Parent: ad.PSOContainer + "," + dom.DN, Attributes: in.Attributes, writeIn: in.writeIn}, "")
}

// psoWrite is ad_policy edit, apply or unapply (ad-password-policy) of one
// PSO. A PSO that already applies to a protected target, or to a group
// reaching one, is refused, and so is applying one to such a user or group.
func (d Deps) psoWrite(ctx context.Context, in adPolicyIn) (map[string]any, error) {
	if n := len(in.AppliesTo); in.Action != "edit" && (n == 0 || n > maxMembers) {
		return nil, fmt.Errorf("%s takes 1 to %d applies_to, got %d: call again for more", in.Action, maxMembers, n)
	}
	var dns []string
	w := adWrite{tool: "ad_policy", action: in.Action, id: in.ID, class: adPSOs.class, in: in.writeIn, attrs: []string{"msDS-PSOAppliesTo"}}
	w.changes = func(e *ldap.Entry) ([]ldap.Change, error) {
		// More values than a search returns at once come as a range: fail closed.
		if slices.ContainsFunc(e.Attributes, func(a *ldap.EntryAttribute) bool { return strings.Contains(a.Name, ";range=") }) {
			return nil, fmt.Errorf("%s applies to too many users and groups to check", e.DN)
		}
		if err := d.reach(ctx, e.GetAttributeValues("msDS-PSOAppliesTo"), e.DN+" already applies to"); err != nil {
			return nil, err
		}
		if in.Action == "edit" {
			return replaces(in.Attributes)
		}
		for _, id := range in.AppliesTo {
			// Get, not Resolve, so a DN is checked against the class too.
			t, err := adGet(d.AD, ctx, id, psoTargets, []string{"1.1"})
			if err != nil {
				return nil, fmt.Errorf("applies_to (a user or global security group) %w", err)
			}
			dns = append(dns, t.DN)
		}
		slices.Sort(dns)
		dns = slices.Compact(dns)
		op := uint(ldap.DeleteAttribute)
		if in.Action == "apply" {
			op = ldap.AddAttribute
			if err := d.reach(ctx, dns, "applies_to"); err != nil {
				return nil, err
			}
		}
		return []ldap.Change{{Operation: op, Modification: ldap.PartialAttribute{Type: "msDS-PSOAppliesTo", Vals: dns}}}, nil
	}
	if in.Action != "edit" {
		w.controls = []ldap.Control{ldap.NewControlString(ldap.ControlTypeMicrosoftPermissiveModify, true, "")}
	}
	out, err := d.adWrite(ctx, w)
	if err != nil {
		return nil, err
	}
	if dns != nil {
		out["applies_to"] = dns
	}
	return out, nil
}

// psoTargets are what a PSO applies to: users and global security groups.
// A global group's members are all in its domain, where Reaches looks.
const psoTargets = "(|(&(objectCategory=person)(objectClass=user))(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483650)))"

// reach refuses when any of dns is, or (a group) reaches, a protected target.
func (d Deps) reach(ctx context.Context, dns []string, what string) error {
	for _, dn := range dns {
		why, err := adReaches(d.AD, ctx, dn)
		if err != nil {
			return fmt.Errorf("%s %w", what, err)
		}
		if why != "" {
			return fmt.Errorf("%s %s: %w: %s", what, dn, ad.ErrProtected, why)
		}
	}
	return nil
}
