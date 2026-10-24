package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

var (
	entraSPs = entraKind{path: "/v1.0/servicePrincipals", typ: "#microsoft.graph.servicePrincipal",
		brief: []string{"id", "appId", "displayName", "servicePrincipalType", "accountEnabled", "appOwnerOrganizationId"},
	}.curated("passwordCredentials", "keyCredentials", "appRoles")
	entraApps = entraKind{path: "/v1.0/applications",
		brief: []string{"id", "appId", "displayName", "signInAudience", "createdDateTime"},
	}.curated("passwordCredentials", "keyCredentials", "appRoles")
	entraRoleDefs = entraKind{path: "/v1.0/roleManagement/directory/roleDefinitions",
		brief: []string{"id", "displayName", "description", "isBuiltIn", "isEnabled", "templateId"}}
	entraSkus = entraKind{path: "/v1.0/subscribedSkus",
		brief: []string{"skuId", "skuPartNumber", "capabilityStatus", "consumedUnits", "prepaidUnits", "appliesTo"}}

	// opaqueID is an id that isn't a GUID: a service health issue's
	// (EX123456) or message's (MC123456), or an Intune detected app's.
	opaqueID      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	entraServices = entraKind{path: "/v1.0/admin/serviceAnnouncement/healthOverviews", brief: []string{"id", "service", "status"}}
	entraIssues   = entraKind{path: "/v1.0/admin/serviceAnnouncement/issues", id: opaqueID,
		brief: []string{"id", "title", "service", "status", "classification", "isResolved", "startDateTime", "lastModifiedDateTime"}}
	entraMessages = entraKind{path: "/v1.0/admin/serviceAnnouncement/messages", id: opaqueID,
		brief: []string{"id", "title", "services", "category", "severity", "isMajorChange", "actionRequiredByDateTime", "lastModifiedDateTime"}}

	credentialSets = []string{"passwordCredentials", "keyCredentials"}
	// credKeys are all of a credential that leaves the server: never
	// secret material (hint, key, secretText).
	credKeys = []string{"keyId", "displayName", "endDateTime"}
)

// creds cuts m's password and key credentials down to credKeys in place,
// and returns them with credential (password or key) added.
func creds(m map[string]any) []map[string]any {
	var all []map[string]any
	for _, set := range credentialSets {
		list, _ := m[set].([]any)
		for i, c := range list {
			c, _ := c.(map[string]any)
			cut := map[string]any{}
			for _, k := range credKeys {
				if v, ok := c[k]; ok {
					cut[k] = v
				}
			}
			list[i] = cut
			tagged := maps.Clone(cut)
			tagged["credential"] = strings.TrimSuffix(set, "Credentials")
			all = append(all, tagged)
		}
	}
	return all
}

func credEnd(c map[string]any) (time.Time, bool) {
	s, _ := c["endDateTime"].(string)
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// nextExpiry sets m's nextCredentialExpiry: the soonest end of cs still ahead.
func nextExpiry(m map[string]any, cs []map[string]any) {
	var soonest time.Time
	for _, c := range cs {
		if t, ok := credEnd(c); ok && t.After(time.Now()) && (soonest.IsZero() || t.Before(soonest)) {
			soonest, m["nextCredentialExpiry"] = t, c["endDateTime"]
		}
	}
}

// appShape cuts the credentials of each result of an app or SP list. An
// app list in its brief (summarise) swaps them for nextCredentialExpiry.
func appShape(out map[string]any, summarise bool) {
	rs, _ := out["results"].([]any)
	for _, r := range rs {
		m, _ := r.(map[string]any)
		cs := creds(m)
		if summarise {
			nextExpiry(m, cs)
			for _, set := range credentialSets {
				delete(m, set)
			}
		}
	}
}

func appSearch(k entraKind, summarise bool) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		def := k.brief
		if summarise {
			def = append(slices.Clone(def), credentialSets...)
		}
		out, err := d.entraList(ctx, k, "", in, def)
		if err == nil {
			appShape(out, summarise && len(in.Fields) == 0)
		}
		return out, err
	}
}

// appGet reads an app or SP with its credentials cut, nextCredentialExpiry,
// and grantedCount: the app role assignments granted to the SP (an app's,
// by its appId).
func appGet(k entraKind) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		out, err := d.entraObject(ctx, k, in, k.get)
		if err != nil {
			return nil, err
		}
		cs := creds(out)
		if len(in.Fields) > 0 {
			return out, nil
		}
		nextExpiry(out, cs)
		sp, _ := k.objectPath(in.ID)
		if k.path == entraApps.path {
			appID, _ := out["appId"].(string)
			sp = "/v1.0/servicePrincipals(appId='" + url.PathEscape(appID) + "')"
		}
		switch p, err := d.Graph.List(ctx, sp+"/appRoleAssignments", graph.Params{Fields: []string{"id"}}, ""); {
		case err != nil:
			out["grantedCount"] = "unavailable: " + err.Error()
		case p.NextCursor != "":
			out["grantedCount"] = fmt.Sprintf("over %d", len(p.Results))
		default:
			out["grantedCount"] = len(p.Results)
		}
		return out, nil
	}
}

// expiringCredentials sweeps every app and SP for credentials that end
// within in.Days from now.
// ponytail: a full sweep of both collections per call; Graph can't filter on credential end dates.
func (d Deps) expiringCredentials(ctx context.Context, in entraIn) (map[string]any, error) {
	days := in.Days
	switch {
	case days == 0:
		days = 30
	case days < 0:
		return nil, errors.New("days must be positive")
	}
	now := time.Now()
	end := now.AddDate(0, 0, days)
	results := []map[string]any{}
	for kind, k := range map[string]entraKind{"app": entraApps, "sp": entraSPs} {
		for cursor := ""; ; {
			p, err := d.Graph.List(ctx, k.path, graph.Params{Fields: append([]string{"id", "appId", "displayName"}, credentialSets...)}, cursor)
			if err != nil {
				return nil, err
			}
			for _, o := range p.Results {
				for _, c := range creds(o) {
					if t, ok := credEnd(c); ok && !t.Before(now) && !t.After(end) {
						results = append(results, map[string]any{"kind": kind, "id": o["id"], "appId": o["appId"], "displayName": o["displayName"],
							"credential": c["credential"], "keyId": c["keyId"], "credentialName": c["displayName"], "endDateTime": c["endDateTime"]})
					}
				}
			}
			if cursor = p.NextCursor; cursor == "" {
				break
			}
		}
	}
	slices.SortFunc(results, func(a, b map[string]any) int {
		ta, _ := credEnd(a)
		tb, _ := credEnd(b)
		return ta.Compare(tb)
	})
	return map[string]any{"window_days": days, "results": results}, nil
}

// roleRows lists role assignments or eligibility schedules at path, each
// with its role definition's and principal's display names.
// ponytail: role definitions listed per call to name them; cache if assignments get hot.
func (d Deps) roleRows(ctx context.Context, path string, in entraIn, def []string) (map[string]any, error) {
	p := graph.Params{Filter: in.Filter, Sort: in.Sort, Fields: def, Expand: "principal"}
	if len(in.Fields) > 0 {
		p = graph.Params{Filter: in.Filter, Sort: in.Sort, Fields: in.Fields}
	}
	page, err := d.Graph.List(ctx, path, p, in.Cursor)
	var ae *graph.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusBadRequest && ae.Code == "AadPremiumLicenseRequired" {
		return nil, errors.New("licence: needs Entra ID P2 (or ID Governance)")
	}
	if err != nil || len(in.Fields) > 0 {
		return obj(page), err
	}
	names := map[any]any{}
	for cursor := ""; ; {
		defs, err := d.Graph.List(ctx, entraRoleDefs.path, graph.Params{Fields: []string{"id", "displayName"}}, cursor)
		if err != nil {
			return nil, err
		}
		for _, r := range defs.Results {
			names[r["id"]] = r["displayName"]
		}
		if cursor = defs.NextCursor; cursor == "" {
			break
		}
	}
	for _, r := range page.Results {
		r["roleDefinition"] = map[string]any{"id": r["roleDefinitionId"], "displayName": names[r["roleDefinitionId"]]}
		pr, _ := r["principal"].(map[string]any)
		r["principal"] = map[string]any{"id": r["principalId"], "displayName": pr["displayName"], "@odata.type": pr["@odata.type"]}
		delete(r, "roleDefinitionId")
		delete(r, "principalId")
	}
	return obj(page), nil
}

func roleList(path string, more ...string) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		return d.roleRows(ctx, path, in, append([]string{"id", "roleDefinitionId", "principalId", "directoryScopeId"}, more...))
	}
}

var orgFields = []string{"id", "displayName", "tenantType", "verifiedDomains", "countryLetterCode", "createdDateTime",
	"onPremisesSyncEnabled", "onPremisesLastSyncDateTime"}

func (d Deps) orgInfo(ctx context.Context, in entraIn) (map[string]any, error) {
	var org struct{ Value []map[string]any }
	if err := d.Graph.Object(ctx, "/v1.0/organization", in.params(orgFields), &org); err != nil {
		return nil, err
	}
	out := map[string]any{}
	if len(org.Value) > 0 {
		out = org.Value[0]
	}
	out["password_writeback"] = map[string]any{"value": d.Config.Entra.PasswordWriteback, "source": "operator-declared"}
	return out, nil
}

var (
	appRead     = []string{"Application.Read.All", "Directory.Read.All"}
	roleRead    = []string{"RoleManagement.Read.Directory", "RoleManagement.Read.All", "Directory.Read.All", "RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"}
	licenceRead = []string{"LicenseAssignment.Read.All", "Organization.Read.All", "Directory.Read.All"}
	orgRead     = []string{"Organization.Read.All", "Directory.Read.All"}
)

func init() {
	roster = append(roster,
		entraTool("entra_app", "identity", "Entra ID applications and service principals",
			"App registrations and service principals (enterprise apps). search_sps: service principals as briefs (id, "+
				"appId, displayName, servicePrincipalType, accountEnabled, appOwnerOrganizationId). get_sp: one by object "+
				"id, with credential expiries, appRoles and grantedCount (app role assignments granted to it) and nextCredentialExpiry. search_apps: "+
				"app registrations as briefs (id, appId, displayName, signInAudience, createdDateTime, nextCredentialExpiry: "+
				"the soonest credential end still ahead). get_app: one by object id (not appId), with the same additions; "+
				"grantedCount is its service principal's. expiring_credentials: every app and SP password or key credential "+
				"ending within days (default 30) from now, soonest first; it sweeps the whole tenant. Credentials carry "+
				"keyId, displayName and endDateTime only: never secret material.",
			nil,
			entraAction{Action{Name: "search_sps", Perms: appRead}, appSearch(entraSPs, false)},
			entraAction{Action{Name: "get_sp", Perms: appRead}, appGet(entraSPs)},
			entraAction{Action{Name: "search_apps", Perms: appRead}, appSearch(entraApps, true)},
			entraAction{Action{Name: "get_app", Perms: appRead}, appGet(entraApps)},
			entraAction{Action{Name: "expiring_credentials", Perms: appRead}, Deps.expiringCredentials},
		),
		entraTool("entra_role", "security", "Entra ID directory roles",
			"Directory roles. definitions: role definitions (id, displayName, description, isBuiltIn, isEnabled, "+
				"templateId). assignments: active role assignments, each with roleDefinition and principal (id, "+
				"displayName, @odata.type) and directoryScopeId (/ is the whole tenant); filter on principalId, "+
				"roleDefinitionId or directoryScopeId. eligibility: PIM eligibility schedules in the same shape, with "+
				"memberType, status and scheduleInfo (needs P2).",
			nil,
			entraAction{Action{Name: "definitions", Perms: roleRead}, entraSearch(entraRoleDefs)},
			entraAction{Action{Name: "assignments", Perms: roleRead}, roleList("/v1.0/roleManagement/directory/roleAssignments")},
			entraAction{Action{Name: "eligibility", Perms: []string{"RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory", "RoleManagement.Read.All"}, Licence: "P2"},
				roleList("/v1.0/roleManagement/directory/roleEligibilitySchedules", "memberType", "status", "scheduleInfo")},
		),
		entraTool("entra_license", "devices", "Entra ID licence SKUs",
			"skus: the tenant's subscribed SKUs (skuId, skuPartNumber, capabilityStatus, consumedUnits, prepaidUnits "+
				"with enabled, suspended and warning units, appliesTo). A user's licences are on entra_user licenses.",
			nil,
			entraAction{Action{Name: "skus", Perms: licenceRead}, entraSearch(entraSkus)},
		),
		entraTool("entra_org", "infra", "Entra ID tenant",
			"info: the tenant (id, displayName, tenantType, verifiedDomains, countryLetterCode, createdDateTime), its "+
				"directory sync (onPremisesSyncEnabled, onPremisesLastSyncDateTime) and password_writeback. Its value is "+
				"operator-declared (--entra-password-writeback): Graph has no reliable writeback flag.",
			nil,
			entraAction{Action{Name: "info", Perms: orgRead}, Deps.orgInfo},
		),
		entraTool("entra_health", "infra", "Microsoft 365 service health",
			"services: each Microsoft 365 service's current health (id, service, status, e.g. serviceDegradation). "+
				"issues: service incidents and advisories as briefs (id, title, service, status, classification, isResolved, "+
				"startDateTime, lastModifiedDateTime); filter e.g. isResolved eq false; with id (such as EX123456), one issue "+
				"in full with its posts. messages: Message Center posts as briefs (id, title, services, category, severity, "+
				"isMajorChange, actionRequiredByDateTime, lastModifiedDateTime); with id (such as MC123456), one in full with its body.",
			nil,
			entraAction{Action{Name: "services", Perms: []string{"ServiceHealth.Read.All"}}, entraSearch(entraServices)},
			entraAction{Action{Name: "issues", Perms: []string{"ServiceHealth.Read.All"}}, listOrGet(entraIssues)},
			entraAction{Action{Name: "messages", Perms: []string{"ServiceMessage.Read.All"}}, listOrGet(entraMessages)},
		),
	)
}
