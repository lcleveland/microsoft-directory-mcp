package tools

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
	"github.com/lcleveland/microsoft-directory-mcp/internal/paging"
)

// logKind is a log or report that refuses $select. Its lists ask for a
// page of paging.Size and cut each row to brief here; sub cuts a nested
// object (or list of them) to its keys. Graph's licence refusal is
// reported as needing licence.
type logKind struct {
	path    string
	licence string
	brief   []string
	sub     map[string][]string
}

var (
	entraAudits = logKind{path: "/v1.0/auditLogs/directoryAudits",
		brief: []string{"activityDateTime", "activityDisplayName", "category", "result", "initiatedBy", "targetResources"},
		sub:   map[string][]string{"targetResources": {"displayName"}}}
	locationBrief = []string{"city", "countryOrRegion"}
	entraSignIns  = logKind{path: "/v1.0/auditLogs/signIns", licence: "P1",
		brief: []string{"createdDateTime", "userPrincipalName", "appDisplayName", "ipAddress", "status", "conditionalAccessStatus", "location"},
		sub:   map[string][]string{"status": {"errorCode"}, "location": locationBrief}}
	entraRiskyUsers = logKind{path: "/v1.0/identityProtection/riskyUsers", licence: "P2",
		brief: []string{"id", "userPrincipalName", "riskLevel", "riskState", "riskLastUpdatedDateTime"}}
	entraRiskDetections = logKind{path: "/v1.0/identityProtection/riskDetections", licence: "P2",
		brief: []string{"id", "detectedDateTime", "riskEventType", "riskLevel", "riskState", "userPrincipalName", "ipAddress", "location"},
		sub:   map[string][]string{"location": locationBrief}}

	entraCAPolicies = entraKind{path: "/v1.0/identity/conditionalAccess/policies",
		brief: []string{"id", "displayName", "state", "modifiedDateTime"}}
	entraNamedLocations = entraKind{path: "/v1.0/identity/conditionalAccess/namedLocations"}
)

// pick keeps keys of m; a key in sub keeps only those keys of its object,
// or of each object in its list.
func pick(m map[string]any, keys []string, sub map[string][]string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		if s := sub[k]; s != nil {
			switch x := v.(type) {
			case map[string]any:
				v = pick(x, s, nil)
			case []any:
				l := make([]any, len(x))
				for i, e := range x {
					if em, ok := e.(map[string]any); ok {
						e = pick(em, s, nil)
					}
					l[i] = e
				}
				v = l
			}
		}
		out[k] = v
	}
	return out
}

func (k logKind) search(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
	if in.Query != "" {
		return nil, errors.New("query works only on entra_user and entra_group search; use filter")
	}
	keys, sub := k.brief, k.sub
	if len(in.Fields) > 0 {
		keys, sub = in.Fields, nil
	}
	p := graph.Params{Filter: in.Filter, Sort: in.Sort, Shape: func(m map[string]any) map[string]any { return pick(m, keys, sub) }}
	page, err := d.Graph.List(ctx, k.path+"?$top="+strconv.Itoa(paging.Size), p, in.Cursor)
	if k.licence != "" && graph.LicenceRefused(err) {
		return nil, fmt.Errorf("licence: needs Entra ID %s (%w)", k.licence, err)
	}
	if err != nil {
		return nil, err
	}
	return obj(page), nil
}

// entraSingle reads the single object at path, such as a policy.
func entraSingle(path string) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		var out map[string]any
		return out, d.Graph.Object(ctx, path, graph.Params{Fields: in.Fields}, &out)
	}
}

const logDoc = " Graph allows these logs about 5 requests per 10 seconds; the server waits out each 429, so keep " +
	"filters narrow, always bounded on the date (e.g. activityDateTime ge 2026-01-01T00:00:00Z), rather than paging " +
	"far. Retention is 7 days on Free and 30 on P1/P2. fields returns those top-level properties of each entry instead " +
	"of the brief."

var (
	auditRead = []string{"AuditLog.Read.All"}
	caRead    = []string{"Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"}
)

func init() {
	roster = append(roster,
		entraTool("entra_audit", "security", "Entra ID directory audit log",
			"search: directory audit events, newest first, as briefs (activityDateTime, activityDisplayName, category, "+
				"result, initiatedBy, targetResources with displayName). Filter on activityDateTime, activityDisplayName, "+
				"category, result, initiatedBy/user/userPrincipalName or targetResources/any(t: t/id eq '…')."+logDoc,
			nil,
			entraAction{Action{Name: "search", Perms: auditRead}, entraAudits.search},
		),
		entraTool("entra_signin", "security", "Entra ID sign-in log",
			"search: interactive user sign-ins, newest first, as briefs (createdDateTime, userPrincipalName, "+
				"appDisplayName, ipAddress, status with errorCode (0 is success), conditionalAccessStatus, location with "+
				"city and countryOrRegion); needs P1. Filter on createdDateTime first, then userPrincipalName, appId, "+
				"ipAddress or status/errorCode. Non-interactive, service-principal and managed-identity sign-ins are beta "+
				"only: entra_api get /beta/auditLogs/signIns with a filter such as signInEventTypes/any(t: t eq "+
				"'nonInteractiveUser') (or 'servicePrincipal', 'managedIdentity') and createdDateTime."+logDoc,
			nil,
			entraAction{Action{Name: "search", Perms: auditRead, Licence: "P1"}, entraSignIns.search},
		),
		entraTool("entra_risk", "security", "Entra ID Identity Protection",
			"Identity Protection; needs P2. risky_users: users at risk as briefs (id, userPrincipalName, "+
				"riskLevel, riskState, riskLastUpdatedDateTime); filter e.g. riskState eq 'atRisk'. risk_detections: risk "+
				"events as briefs (id, detectedDateTime, riskEventType, riskLevel, riskState, userPrincipalName, ipAddress, "+
				"location); filter on userId, riskEventType or detectedDateTime. Graph allows Identity Protection about 1 "+
				"request per second per tenant, shared by every app; keep filters narrow.",
			entraRiskDoc,
			entraAction{Action{Name: "risky_users", Perms: []string{"IdentityRiskyUser.Read.All", "IdentityRiskyUser.ReadWrite.All"}, Licence: "P2"}, entraRiskyUsers.search},
			entraAction{Action{Name: "risk_detections", Perms: []string{"IdentityRiskEvent.Read.All"}, Licence: "P2"}, entraRiskDetections.search},
			entraRiskAction("confirm_compromised"), entraRiskAction("dismiss"),
		),
		entraTool("entra_policy", "policy", "Entra ID policies",
			"Tenant policies, read only. conditional_access: Conditional Access policies as briefs (id, displayName, "+
				"state, modifiedDateTime); with id, one policy in full (conditions, grantControls, sessionControls). "+
				"named_locations: the named locations (IP ranges, countries). auth_methods_policy: the authentication "+
				"methods policy and each method's configuration. security_defaults: whether security defaults are on. "+
				"Graph allows Conditional Access about 1 request per second per tenant, shared by every app; read one policy rather than many.",
			nil,
			entraAction{Action{Name: "conditional_access", Perms: caRead}, func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
				if in.ID != "" {
					return entraGet(entraCAPolicies)(d, ctx, in)
				}
				return entraSearch(entraCAPolicies)(d, ctx, in)
			}},
			entraAction{Action{Name: "named_locations", Perms: caRead}, entraSearch(entraNamedLocations)},
			entraAction{Action{Name: "auth_methods_policy", Perms: []string{"Policy.Read.AuthenticationMethod", "Policy.ReadWrite.AuthenticationMethod"}},
				entraSingle("/v1.0/policies/authenticationMethodsPolicy")},
			entraAction{Action{Name: "security_defaults", Perms: []string{"Policy.Read.All", "Policy.ReadWrite.SecurityDefaults"}},
				entraSingle("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")},
		),
	)
}
