package tools

import (
	"context"
	"errors"

	"github.com/go-ldap/ldap/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
)

var (
	adTrusts = adKind{class: "(objectClass=trustedDomain)",
		brief: []string{"dn", "trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes", "whenCreated"}}
	adSubnets = adKind{class: "(objectClass=subnet)", brief: []string{"dn", "name", "siteObject", "location", "description"}}
)

// listing is an unpaged list, with the domains or DCs left out.
type listing[T any] struct {
	Results []T          `json:"results"`
	Skipped []ad.Skipped `json:"_skipped,omitempty"`
}

func list[T any](r []T, skipped []ad.Skipped, err error) (map[string]any, error) {
	if err != nil {
		return nil, err
	}
	return obj(listing[T]{append([]T{}, r...), skipped}), nil
}

type adTopologyIn struct {
	ActionParam
	Domain string `json:"domain,omitempty" jsonschema:"trusts, dcs, fsmo, replication: only this domain (DNS or NetBIOS name)"`
	Cursor string `json:"cursor,omitempty" jsonschema:"trusts, subnets: next_cursor from the previous call with the same arguments, unchanged"`
}

// lockout is ad_user lockout.
func (d Deps) lockout(ctx context.Context, in adIn) (map[string]any, error) {
	if in.ID == "" {
		return nil, errors.New("lockout needs id")
	}
	e, err := d.AD.Get(ctx, in.ID, adUsers.class, ad.LockoutAttrs)
	if err != nil {
		return nil, err
	}
	l, err := d.AD.Lockout(ctx, e)
	if err != nil {
		return nil, err
	}
	return obj(l), nil
}

// lastLogon is ad_user and ad_computer last_logon: the account's lastLogon
// from every DC of its domain.
func lastLogon(k adKind) adExtra {
	return adExtra{Action: Action{Name: "last_logon"}, run: func(d Deps, ctx context.Context, in adIn) (map[string]any, error) {
		if in.ID == "" {
			return nil, errors.New("last_logon needs id")
		}
		dn, err := d.AD.Resolve(ctx, in.ID, k.class)
		if err != nil {
			return nil, err
		}
		l, err := d.AD.LastLogon(ctx, dn)
		if err != nil {
			return nil, err
		}
		return obj(l), nil
	}}
}

const lastLogonDoc = " last_logon: the account's true last logon by id: lastLogon, which each DC keeps for itself, read " +
	"from every DC of its domain; the latest as lastLogon with the DC holding it as lastLogon_dc (null: never), and " +
	"per_dc. A DC that can't be reached is in _skipped and may hold a later one."

var adTopologyTool = Tool{Name: "ad_topology", Group: "infra", Actions: []Action{{Name: "domains"}, {Name: "trusts"},
	{Name: "sites"}, {Name: "subnets"}, {Name: "dcs"}, {Name: "fsmo"}, {Name: "replication", ADProbe: "repl-read"}},
	add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
		addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Active Directory topology", Annotations: readOnly,
			Description: "The forest's topology and replication, from LDAP alone. domains: each domain (dns, netbios, dn). " +
				"trusts: each domain's trustedDomain objects (trustPartner, flatName, trustDirection, trustType, trustAttributes " +
				"flags). sites: each site with how many subnets and DCs it has. subnets: each subnet with its siteObject. dcs: " +
				"every DC from the configuration partition (dNSHostName, domain, site, isGC, isPDC, reachable: whether it " +
				"answered a bind just now). fsmo: the holders of the schema and domain_naming roles and of each domain's pdc, " +
				"rid and infrastructure roles. replication: every DC's inbound replication partners per naming context " +
				"(last success, last attempt, last_result as a Win32 error code, consecutive failures), KCC connection and " +
				"link failures and pending operation count, read from each DC's rootDSE msDS-Repl* attributes; a DC that " +
				"can't be reached is listed in _skipped. It cannot force a sync. domain narrows trusts, dcs, fsmo and " +
				"replication to one domain."},
			visible, func(ctx context.Context, _ *mcp.CallToolRequest, in adTopologyIn) (*mcp.CallToolResult, map[string]any, error) {
				var (
					out map[string]any
					err error
				)
				switch in.Action {
				case "domains":
					var ds []ad.Domain
					ds, err = d.AD.Domains(ctx)
					out, err = list(ds, nil, err)
				case "trusts":
					out, err = d.search(ctx, adTrusts, adIn{Domain: in.Domain, Cursor: in.Cursor}, ad.Query{Under: "CN=System", Scope: ldap.ScopeSingleLevel})
				case "sites":
					var ss []ad.Site
					ss, err = d.AD.Sites(ctx)
					out, err = list(ss, nil, err)
				case "subnets":
					var root *ad.RootDSE
					if _, _, root, err = d.AD.Root(ctx); err != nil {
						return nil, nil, err
					}
					out, err = d.search(ctx, adSubnets, adIn{Cursor: in.Cursor},
						ad.Query{Base: "CN=Subnets,CN=Sites," + root.ConfigurationNamingContext, Scope: ldap.ScopeSingleLevel})
				case "dcs":
					out, err = list(d.AD.DCs(ctx, in.Domain))
				case "fsmo":
					out, err = list(d.AD.FSMO(ctx, in.Domain))
				default:
					out, err = list(d.AD.Replication(ctx, in.Domain))
				}
				return nil, out, err
			})
	}}
