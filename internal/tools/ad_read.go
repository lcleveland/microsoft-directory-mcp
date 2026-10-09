package tools

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/paging"
)

// adKind is what an ad_* tool reads: its object class filter, the brief
// keys lists return and the curated keys gets return. Keys are LDAP names,
// plus dn and the derived enabled, memberCount, linkCount and appliesToCount.
// derive, if set, adds or rewrites keys of a decoded entry.
type adKind struct {
	class      string
	brief, get []string
	derive     func(map[string]any)
}

// shape renders a decoded entry of k as keys.
func (k adKind) shape(keys []string) func(map[string]any) map[string]any {
	return func(m map[string]any) map[string]any {
		if k.derive != nil {
			k.derive(m)
		}
		return project(m, keys)
	}
}

func (k adKind) curated(more ...string) adKind {
	k.get = append(slices.Clone(k.brief), more...)
	return k
}

var (
	adUsers = adKind{class: "(&(objectCategory=person)(objectClass=user))",
		brief: []string{"dn", "sAMAccountName", "userPrincipalName", "displayName", "mail", "enabled", "objectSid", "lastLogonTimestamp", "whenCreated"},
	}.curated("pwdLastSet", "lockoutTime", "accountExpires", "msDS-UserPasswordExpiryTimeComputed", "title", "department",
		"manager", "employeeID", "description", "memberOf", "adminCount", "servicePrincipalName", "whenChanged", "userAccountControl", "msDS-ObjectSoa")
	adGroups = adKind{class: "(objectClass=group)",
		brief: []string{"dn", "sAMAccountName", "displayName", "groupType", "description", "objectSid"},
	}.curated("managedBy", "memberCount", "memberOf", "adminCount", "whenChanged", "msDS-ObjectSoa")
	adComputers = adKind{class: "(objectClass=computer)",
		brief: []string{"dn", "sAMAccountName", "dNSHostName", "enabled", "objectSid", "lastLogonTimestamp", "whenCreated"},
	}.curated("operatingSystem", "operatingSystemVersion", "managedBy", "description", "servicePrincipalName",
		"msDS-SupportedEncryptionTypes", "whenChanged", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "msDS-ObjectSoa")
	adObjects = adKind{class: "(objectClass=*)",
		brief: []string{"dn", "objectClass", "name", "sAMAccountName", "displayName", "objectSid", "objectGUID", "whenCreated", "whenChanged"},
	}.curated()
	adDeleted = adKind{class: "(isDeleted=TRUE)",
		brief: []string{"dn", "name", "objectClass", "sAMAccountName", "lastKnownParent", "objectSid", "objectGUID", "whenChanged"}}
)

// dnCap caps each multi-valued attribute of a get.
const dnCap = 100

// attrs maps keys to the LDAP attributes to request.
func attrs(keys []string) []string {
	var out []string
	for _, k := range keys {
		switch strings.ToLower(k) {
		case "dn", "membercount":
		case "enabled":
			out = append(out, "userAccountControl")
		case "linkcount":
			out = append(out, "gPLink")
		case "appliestocount":
			out = append(out, "msDS-PSOAppliesTo")
		default:
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// project keeps keys (any case) of a decoded entry, and dn.
func project(m map[string]any, keys []string) map[string]any {
	out := map[string]any{"dn": m["dn"]}
	for k, v := range m {
		if slices.ContainsFunc(keys, func(f string) bool { return strings.EqualFold(f, k) }) {
			out[k] = v
		}
	}
	return out
}

// joinFilter ANDs the parts that are set, parenthesizing a bare one, and
// checks the result parses.
func joinFilter(parts ...string) (string, error) {
	f := ""
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.HasPrefix(p, "(") {
				p = "(" + p + ")"
			}
			f += p
		}
	}
	f = "(&" + f + ")"
	if _, err := ldap.CompileFilter(f); err != nil {
		return "", fmt.Errorf("filter %s: %w (see the ad://guide/ldap-filter resource)", f, err)
	}
	return f, nil
}

// obj turns a result struct into the map tools return.
func obj(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

type adIn struct {
	ActionParam
	ID     string   `json:"id,omitempty" jsonschema:"get, members: a DN, SID (S-1-…), GUID, UPN (has @), sAMAccountName, or DOMAIN\\sam"`
	Query  string   `json:"query,omitempty" jsonschema:"search: name lookup by ambiguous name resolution (sAMAccountName, displayName, givenName, sn, mail and others; prefix match)"`
	Filter string   `json:"filter,omitempty" jsonschema:"search: raw LDAP filter, ANDed with the object class; read the ad://guide/ldap-filter resource first"`
	Domain string   `json:"domain,omitempty" jsonschema:"search, transitive members: only this domain (DNS or NetBIOS name) instead of every domain of the forest"`
	Fields []string `json:"fields,omitempty" jsonschema:"LDAP attribute names to return instead of the default set (enabled is derived from userAccountControl); binary attributes come base64"`
	Cursor string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call with the same arguments, unchanged"`
}

// keys are the fields asked for, or def.
func (in adIn) keys(def []string) []string {
	if len(in.Fields) > 0 {
		return in.Fields
	}
	return def
}

type adGroupIn struct {
	adIn
	Transitive bool `json:"transitive,omitempty" jsonschema:"members: every nested member, not only direct ones"`
}

// search runs a fanned-out list of k, narrowed by the input.
func (d Deps) search(ctx context.Context, k adKind, in adIn, q ad.Query) (map[string]any, error) {
	anr := ""
	if in.Query != "" {
		anr = "(anr=" + ldap.EscapeFilter(in.Query) + ")"
	}
	f, err := joinFilter(k.class, in.Filter, anr)
	if err != nil {
		return nil, err
	}
	keys := in.keys(k.brief)
	q.Domain, q.Filter, q.Attrs = in.Domain, f, attrs(keys)
	q.Shape = k.shape(keys)
	p, err := d.AD.Search(ctx, q, in.Cursor)
	if err != nil {
		return nil, err
	}
	return obj(p), nil
}

// get reads one object of k, capping multi-valued attributes at dnCap.
func (d Deps) get(ctx context.Context, k adKind, in adIn) (map[string]any, error) {
	if in.ID == "" {
		return nil, errors.New("get needs id")
	}
	keys := in.keys(k.get)
	e, err := d.AD.Get(ctx, in.ID, k.class, attrs(keys))
	if err != nil {
		return nil, err
	}
	out := k.shape(keys)(ad.Decode(e, attrs(keys)))
	trunc := map[string]any{}
	for key, v := range out {
		if l, ok := v.([]any); ok && len(l) > dnCap {
			out[key] = l[:dnCap]
			trunc[key] = map[string]int{"returned": dnCap, "of": len(l)}
		}
	}
	if len(trunc) > 0 {
		out["_truncation"] = trunc
	}
	// ponytail: memberCount reads every member, 1500 a round trip; fine to tens of thousands.
	if slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, "memberCount") }) {
		n := 0
		for off := 0; off >= 0; {
			var vals []string
			if vals, off, err = d.AD.Values(ctx, e.DN, "member", off, 1500); err != nil {
				return nil, err
			}
			n += len(vals)
		}
		out["memberCount"] = n
	}
	if j, ok := joinOf(k.class); ok && len(in.Fields) == 0 {
		sid, _ := out["objectSid"].(string)
		_, soa := ad.Field(out, "msDS-ObjectSoa")
		soaS, _ := soa.(string)
		d.addCounterpart(out, func() (*Counterpart, error) { return d.fromAD(ctx, j, sid, soaS) })
	}
	return out, nil
}

// members pages a group's members as briefs of their own kind. Direct
// members page by range-retrieval offset; transitive ones by a paged
// in-chain search across the forest.
func (d Deps) members(ctx context.Context, in adGroupIn) (map[string]any, error) {
	if in.ID == "" {
		return nil, errors.New("members needs id")
	}
	g, err := d.AD.Get(ctx, in.ID, adGroups.class, []string{"1.1"})
	if err != nil {
		return nil, err
	}
	dn := g.DN
	var all []string
	for _, k := range []adKind{adUsers, adGroups, adComputers} {
		all = append(all, k.brief...)
	}
	keys := in.keys(append(all, "objectClass"))
	shape := func(m map[string]any) map[string]any {
		if len(in.Fields) > 0 {
			return project(m, keys)
		}
		cls, _ := m["objectClass"].([]any)
		has := func(c string) bool { return slices.Contains(cls, any(c)) }
		var k []string
		switch {
		case has("computer"):
			k = adComputers.brief
		case has("group"):
			k = adGroups.brief
		case has("user"):
			k = adUsers.brief
		default:
			k = []string{"name", "sAMAccountName", "objectSid"}
		}
		return project(m, append(k, "objectClass"))
	}
	if in.Transitive {
		f := "(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(dn) + ")"
		p, err := d.AD.Search(ctx, ad.Query{Domain: in.Domain, Filter: f, Attrs: attrs(keys), Shape: shape}, in.Cursor)
		if err != nil {
			return nil, err
		}
		return obj(p), nil
	}

	bind := fmt.Sprint(dn, in.Fields)
	off, err := decodeOffset(in.Cursor, bind)
	if err != nil {
		return nil, err
	}
	dns, next, err := d.AD.Values(ctx, dn, "member", off, paging.Size)
	if err != nil {
		return nil, err
	}
	ents, err := d.AD.ReadMany(ctx, dns, attrs(keys))
	if err != nil {
		return nil, err
	}
	p := ad.Page{Results: make([]map[string]any, len(ents))}
	for i, e := range ents {
		p.Results[i] = shape(e)
	}
	if kept, t := paging.Trim(p.Results); t != nil {
		p.Results, p.Truncation, next = p.Results[:kept], t, off+kept
	}
	p.NextCursor = encodeOffset(next, bind)
	return obj(p), nil
}

// A direct-members cursor is the next range offset, bound to the query.
type offsetCursor struct {
	Off  int    `json:"o"`
	Bind string `json:"b"`
}

func encodeOffset(off int, bind string) string {
	if off < 0 {
		return ""
	}
	b, _ := json.Marshal(offsetCursor{off, bind})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeOffset(cursor, bind string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	var c offsetCursor
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.Bind != bind || c.Off < 0 {
		return 0, paging.ErrForeignCursor
	}
	return c.Off, nil
}

type adAPIIn struct {
	ActionParam
	Base       string   `json:"base" jsonschema:"search: the DN to search under; it is routed to a domain controller of the domain owning it"`
	Scope      string   `json:"scope,omitempty" jsonschema:"search: base, one or sub (the default)"`
	Filter     string   `json:"filter,omitempty" jsonschema:"search: raw LDAP filter, default (objectClass=*); read the ad://guide/ldap-filter resource first"`
	Attributes []string `json:"attributes,omitempty" jsonschema:"search: LDAP attributes to return, default all; binary attributes come base64 only when named"`
	Cursor     string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call with the same arguments, unchanged"`
}

const adSearchDoc = "Lists search every domain of the forest (domain narrows to one), page 200 at a time with next_cursor " +
	"(expires after 10 idle minutes), and are unsorted; a domain that can't be reached is listed in _skipped. " +
	"Keys are LDAP attribute names; values are decoded (SIDs, GUIDs, times as RFC 3339 UTC, null for never). " +
	"filter takes a raw LDAP filter: read the ad://guide/ldap-filter resource first."

// adExtra is an action of an adReadTool beyond search and get, or one
// replacing them.
type adExtra struct {
	Action
	run func(Deps, context.Context, adIn) (map[string]any, error)
}

func adReadTool(name, group, title, desc string, k adKind, extra ...adExtra) Tool {
	actions := []Action{{Name: "search"}, {Name: "get"}}
	for _, x := range extra {
		if i := slices.IndexFunc(actions, func(a Action) bool { return a.Name == x.Name }); i >= 0 {
			actions[i] = x.Action
		} else {
			actions = append(actions, x.Action)
		}
	}
	return Tool{Name: name, Group: group, Actions: actions,
		add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
			addActionTool(s, d, t, &mcp.Tool{Name: name, Title: title, Description: desc + "\n\n" + adSearchDoc, Annotations: readOnly}, visible,
				func(ctx context.Context, _ *mcp.CallToolRequest, in adIn) (*mcp.CallToolResult, map[string]any, error) {
					for _, x := range extra {
						if x.Name == in.Action {
							out, err := x.run(d, ctx, in)
							return nil, out, err
						}
					}
					if in.Action == "get" {
						out, err := d.get(ctx, k, in)
						return nil, out, err
					}
					out, err := d.search(ctx, k, in, ad.Query{})
					return nil, out, err
				})
		}}
}

func init() {
	roster = append(roster,
		adReadTool("ad_user", "identity", "Active Directory users",
			"Users of the forest. search: list users by query (name) or filter, as briefs (dn, sAMAccountName, "+
				"userPrincipalName, displayName, mail, enabled, objectSid, lastLogonTimestamp, whenCreated). get: one user by id, "+
				"with password, lockout and expiry times, title, department, manager, memberOf (first 100), "+
				"servicePrincipalName and userAccountControl flags. lastLogonTimestamp replicates lazily (up to 14 days behind). "+
				"resultant_policy: the password and lockout policy that applies to the user by id: the PSO msDS-ResultantPSO "+
				"names (as ad_policy psos gets it), else its domain's default policy. lockout: why a user by id is locked "+
				"out, as LDAP shows it: lockoutTime, msDS-User-Account-Control-Computed flags (LOCKOUT), lockoutTime_origin "+
				"(the DC that originated the last lockoutTime write, from replication metadata) and per_dc badPwdCount and "+
				"badPasswordTime from every DC of the user's domain (they don't replicate; unreachable DCs in _skipped). "+
				"The machine the bad passwords came from (event 4740) is not read."+counterpartDoc, adUsers,
			adExtra{Action{Name: "resultant_policy", ADProbe: "pso-read"}, Deps.resultantPolicy}, adExtra{Action{Name: "lockout"}, Deps.lockout}),
		Tool{Name: "ad_group", Group: "identity", Actions: []Action{{Name: "search"}, {Name: "get"}, {Name: "members"}},
			add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
				addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Active Directory groups", Annotations: readOnly,
					Description: "Groups of the forest. search: list groups as briefs (dn, sAMAccountName, displayName, " +
						"groupType scope and type, description, objectSid). get: one group by id, with managedBy, memberCount, " +
						"memberOf (first 100) and adminCount, but not its members. members: the group's members as briefs " +
						"of their own kind, 200 a page; transitive=true lists every nested member instead (each once)." + counterpartDoc + "\n\n" + adSearchDoc},
					visible, func(ctx context.Context, _ *mcp.CallToolRequest, in adGroupIn) (*mcp.CallToolResult, map[string]any, error) {
						var (
							out map[string]any
							err error
						)
						switch in.Action {
						case "get":
							out, err = d.get(ctx, adGroups, in.adIn)
						case "members":
							out, err = d.members(ctx, in)
						default:
							out, err = d.search(ctx, adGroups, in.adIn, ad.Query{})
						}
						return nil, out, err
					})
			}},
		adReadTool("ad_computer", "devices", "Active Directory computers",
			"Computer accounts of the forest. search: list computers as briefs (dn, sAMAccountName, dNSHostName, "+
				"enabled, objectSid, lastLogonTimestamp, whenCreated). get: one computer by id, with operating system "+
				"and version, managedBy, servicePrincipalName, supported encryption types and the LAPS password expiry "+
				"(never the password)."+counterpartDoc, adComputers),
		adOUTool,
		Tool{Name: "ad_object", Group: "identity", Actions: []Action{{Name: "get"}, {Name: "search_deleted"}},
			add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
				addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Any Active Directory object", Annotations: readOnly,
					Description: "Any object of the forest. get: one object of any class by id (dn, objectClass, name, " +
						"sAMAccountName, displayName, objectSid, objectGUID, whenCreated, whenChanged; fields for more). " +
						"search_deleted: deleted objects still in each domain's Deleted Objects container, with " +
						"lastKnownParent, narrowed by query or filter.\n\n" + adSearchDoc},
					visible, func(ctx context.Context, _ *mcp.CallToolRequest, in adIn) (*mcp.CallToolResult, map[string]any, error) {
						if in.Action == "get" {
							out, err := d.get(ctx, adObjects, in)
							return nil, out, err
						}
						out, err := d.search(ctx, adDeleted, in, ad.Query{Under: "CN=Deleted Objects", Scope: ldap.ScopeSingleLevel, ShowDeleted: true})
						return nil, out, err
					})
			}},
		adGPOTool,
		adPolicyTool,
		adTopologyTool,
		Tool{Name: "ad_api", Group: "core", Actions: []Action{{Name: "search"}},
			add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
				addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Raw Active Directory search", Annotations: readOnly,
					Description: "Raw LDAP search when no ad_* tool fits. search: base (a DN), scope, filter and " +
						"attributes, against a domain controller of the domain owning base (configuration and schema go " +
						"to the forest root domain). Values are decoded as in the other ad_* tools; pages of 200 " +
						"with next_cursor. Read the ad://guide/ldap-filter resource before writing a filter."},
					visible, func(ctx context.Context, _ *mcp.CallToolRequest, in adAPIIn) (*mcp.CallToolResult, map[string]any, error) {
						scope, ok := map[string]int{"": ldap.ScopeWholeSubtree, "sub": ldap.ScopeWholeSubtree,
							"one": ldap.ScopeSingleLevel, "base": ldap.ScopeBaseObject}[in.Scope]
						if !ok {
							return nil, nil, fmt.Errorf("scope %q: want base, one or sub", in.Scope)
						}
						if in.Base == "" {
							return nil, nil, errors.New("search needs base")
						}
						f, err := joinFilter(cmp.Or(in.Filter, "(objectClass=*)"))
						if err != nil {
							return nil, nil, err
						}
						p, err := d.AD.Search(ctx, ad.Query{Base: in.Base, Scope: scope, Filter: f, Attrs: in.Attributes}, in.Cursor)
						if err != nil {
							return nil, nil, err
						}
						return nil, obj(p), nil
					})
			}},
	)
}

//go:embed ldap-filter.md
var ldapFilterGuide string

// registerADGuides adds the LDAP filter guide the ad_* tools point to.
func registerADGuides(s *mcp.Server) {
	addGuide(s, "ad://guide/ldap-filter", "ldap-filter", ldapFilterGuide,
		"How to write the filter of ad_* searches: LDAP filter syntax, escaping, and filters for common questions.")
}

func addGuide(s *mcp.Server, uri, name, text, desc string) {
	s.AddResource(&mcp.Resource{URI: uri, Name: name, MIMEType: "text/markdown", Description: desc},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "text/markdown", Text: text}}}, nil
		})
}
