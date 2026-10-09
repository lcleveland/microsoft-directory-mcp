package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// entraKind is what an entra_* tool reads: its collection, the brief
// properties lists select, the curated ones gets select (nil: all), and
// the get's $expand.
type entraKind struct {
	path       string
	brief, get []string
	expand     string
	upnOK      bool   // get takes a UPN as well as an object id
	searchable bool   // lists take query ($search on displayName and mail)
	typ        string // @odata.type of its objects in mixed relations
}

func (k entraKind) curated(more ...string) entraKind {
	k.get = append(slices.Clone(k.brief), more...)
	return k
}

var (
	entraUsers = entraKind{path: "/v1.0/users", upnOK: true, searchable: true, typ: "#microsoft.graph.user", expand: "manager($select=id,displayName)",
		brief: []string{"id", "userPrincipalName", "displayName", "mail", "accountEnabled", "onPremisesSyncEnabled", "userType", "createdDateTime"},
	}.curated("onPremisesSamAccountName", "onPremisesSecurityIdentifier", "onPremisesLastSyncDateTime", "jobTitle", "department", "assignedLicenses", "signInActivity", "lastPasswordChangeDateTime")
	entraGroups = entraKind{path: "/v1.0/groups", searchable: true, typ: "#microsoft.graph.group",
		brief: []string{"id", "displayName", "mail", "securityEnabled", "mailEnabled", "groupTypes", "onPremisesSyncEnabled"},
	}.curated("description", "membershipRule", "isAssignableToRole", "onPremisesSecurityIdentifier")
	entraDevices = entraKind{path: "/v1.0/devices", typ: "#microsoft.graph.device", expand: "registeredOwners($select=" + strings.Join(entraUsers.brief, ",") + ")",
		brief: []string{"id", "deviceId", "displayName", "operatingSystem", "accountEnabled", "trustType", "approximateLastSignInDateTime"},
	}.curated("operatingSystemVersion", "isCompliant", "isManaged", "onPremisesSyncEnabled", "onPremisesSecurityIdentifier")
	entraManaged = entraKind{path: "/v1.0/deviceManagement/managedDevices",
		brief: []string{"id", "deviceName", "operatingSystem", "osVersion", "complianceState", "lastSyncDateTime", "userPrincipalName"}}

	// directoryObjects selects the union of the briefs, for relations whose
	// members are of mixed kinds; each comes back as its own kind's brief.
	directoryObjects = slices.Compact(slices.Sorted(slices.Values(slices.Concat(entraUsers.brief, entraGroups.brief, entraDevices.brief))))
)

var objectID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// objectPath is k's path to the object id names (a UPN too for users).
func (k entraKind) objectPath(id string) (string, error) {
	switch {
	case objectID.MatchString(id):
	case k.upnOK && strings.Contains(id, "@") && !strings.ContainsAny(id, "/?#"):
	case k.upnOK:
		return "", fmt.Errorf("id %q: want an object id (GUID) or a UPN", id)
	default:
		return "", fmt.Errorf("id %q: want an object id (GUID)", id)
	}
	return k.path + "/" + url.PathEscape(id), nil
}

// entraShape renders a directory object as the brief of its kind, keeping
// @odata.type.
func entraShape(m map[string]any) map[string]any {
	keys := []string{"id", "displayName"}
	for _, k := range []entraKind{entraUsers, entraGroups, entraDevices} {
		if m["@odata.type"] == k.typ {
			keys = k.brief
		}
	}
	out := map[string]any{"@odata.type": m["@odata.type"]}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

type entraIn struct {
	ActionParam
	ID     string   `json:"id,omitempty" jsonschema:"every action but search: the object id (a GUID); entra_user also takes a UPN"`
	Filter string   `json:"filter,omitempty" jsonschema:"lists: OData $filter, passed through; read the entra://guide/odata-filter resource first"`
	Query  string   `json:"query,omitempty" jsonschema:"search: quick lookup by displayName or mail (word prefix)"`
	Sort   string   `json:"sort,omitempty" jsonschema:"lists: OData $orderby, e.g. displayName desc"`
	Fields []string `json:"fields,omitempty" jsonschema:"Graph property names to return instead of the default set"`
	Cursor string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call with the same arguments, unchanged"`
	// Only on entra_group.
	Transitive bool `json:"transitive,omitempty" jsonschema:"entra_group members: every nested member, not only direct ones"`
	// Only on entra_user.
	MustChange *bool  `json:"must_change,omitempty" jsonschema:"writes, reset_password: make the user change the password at next sign-in; default true"`
	MethodID   string `json:"method_id,omitempty" jsonschema:"writes, delete_auth_method: the id of the authentication method, from auth_methods"`
	// Only on entra_group.
	Members []string `json:"members,omitempty" jsonschema:"writes, add_members, remove_members: up to 20 members by object id (a GUID)"`
	// Only on entra_app.
	Days int `json:"days,omitempty" jsonschema:"entra_app expiring_credentials: the window in days from now (default 30)"`
	writeIn
}

func (in entraIn) params(def []string) graph.Params {
	p := graph.Params{Filter: in.Filter, Query: in.Query, Sort: in.Sort, Fields: def}
	if len(in.Fields) > 0 {
		p.Fields = in.Fields
	}
	return p
}

// entraList pages rel under the object in.ID of k (rel "" lists k itself).
// Mixed relations are shaped by kind unless fields were asked for.
func (d Deps) entraList(ctx context.Context, k entraKind, rel string, in entraIn, def []string) (map[string]any, error) {
	if in.Query != "" && (!k.searchable || rel != "") {
		return nil, errors.New("query works only on entra_user and entra_group search; use filter")
	}
	path := k.path
	if rel != "" {
		var err error
		if path, err = k.objectPath(in.ID); err != nil {
			return nil, err
		}
		path += rel
	}
	p, err := d.Graph.List(ctx, path, in.params(def), in.Cursor)
	if err != nil {
		return nil, err
	}
	if slices.Equal(def, directoryObjects) && len(in.Fields) == 0 {
		for i, r := range p.Results {
			p.Results[i] = entraShape(r)
		}
	}
	return obj(p), nil
}

// entraObject reads in.ID of k with its curated set, or fields.
func (d Deps) entraObject(ctx context.Context, k entraKind, in entraIn, curated []string) (map[string]any, error) {
	path, err := k.objectPath(in.ID)
	if err != nil {
		return nil, err
	}
	p := graph.Params{Fields: curated, Expand: k.expand}
	if len(in.Fields) > 0 {
		p = graph.Params{Fields: in.Fields}
	}
	var out map[string]any
	return out, d.Graph.Object(ctx, path, p, &out)
}

// signInActivity is what selecting it on a user needs.
var signInActivity = Action{Name: "signInActivity", Perms: []string{"AuditLog.Read.All"}, Licence: "P1"}

func (d Deps) userGet(ctx context.Context, in entraIn) (map[string]any, error) {
	// Without signInActivity when the probe hides it, or when Graph refuses
	// it (the probe could not decide P1).
	var out map[string]any
	var err error
	var ae *graph.APIError
	hidden := len(in.Fields) == 0 && d.why(Tool{Name: "entra_user", Group: "identity"}, signInActivity) != ""
	if !hidden {
		out, err = d.entraObject(ctx, entraUsers, in, entraUsers.get)
	}
	if hidden || len(in.Fields) == 0 && errors.As(err, &ae) && ae.Status == http.StatusForbidden {
		without := slices.DeleteFunc(slices.Clone(entraUsers.get), func(f string) bool { return f == signInActivity.Name })
		if out, err = d.entraObject(ctx, entraUsers, in, without); err == nil {
			out["_omitted"] = map[string]string{signInActivity.Name: "needs an Entra ID P1 licence and AuditLog.Read.All"}
		}
	}
	if err != nil {
		return nil, err
	}
	d.nameSkus(ctx, out)
	if len(in.Fields) == 0 {
		d.addCounterpart(out, func() (*Counterpart, error) { return d.fromEntra(ctx, joinUser, out) })
	}
	return out, nil
}

// nameSkus adds skuPartNumber to the licences of a user, from
// subscribedSkus. Without LicenseAssignment.Read.All they keep skuId only.
func (d Deps) nameSkus(ctx context.Context, user map[string]any) {
	var lics []any
	for _, k := range []string{"assignedLicenses", "licenseAssignmentStates"} {
		l, _ := user[k].([]any)
		lics = append(lics, l...)
	}
	if len(lics) == 0 {
		return
	}
	var skus struct {
		Value []struct{ SkuID, SkuPartNumber string }
	}
	// ponytail: subscribedSkus per call; cache it if user gets get hot.
	if d.Graph.Get(ctx, "/v1.0/subscribedSkus?$select=skuId,skuPartNumber", &skus) != nil {
		return
	}
	for _, l := range lics {
		if m, ok := l.(map[string]any); ok {
			for _, s := range skus.Value {
				if m["skuId"] == s.SkuID {
					m["skuPartNumber"] = s.SkuPartNumber
				}
			}
		}
	}
}

// userDevices lists the devices a user owns and has registered, tagged
// with the relation; a device in both comes once with both.
// ponytail: first page of each; a user with over 200 devices gets _truncation, page with entra_api.
func (d Deps) userDevices(ctx context.Context, in entraIn) (map[string]any, error) {
	base, err := entraUsers.objectPath(in.ID)
	if err != nil {
		return nil, err
	}
	var results []map[string]any
	out := map[string]any{}
	for _, rel := range []string{"owned", "registered"} {
		p, err := d.Graph.List(ctx, base+"/"+rel+"Devices", graph.Params{Fields: entraIn{Fields: in.Fields}.params(entraDevices.brief).Fields}, "")
		if err != nil {
			return nil, err
		}
		if p.NextCursor != "" {
			out["_truncation"] = "only the first page of " + rel + "Devices; page it with entra_api"
		}
		for _, r := range p.Results {
			if i := slices.IndexFunc(results, func(x map[string]any) bool { return x["id"] == r["id"] }); i >= 0 {
				results[i]["relation"] = append(results[i]["relation"].([]string), rel)
				continue
			}
			r["relation"] = []string{rel}
			results = append(results, r)
		}
	}
	out["results"] = results
	return obj(out), nil
}

// registration reads a user's userRegistrationDetails, which is keyed by
// object id only.
func (d Deps) registration(ctx context.Context, in entraIn) (map[string]any, error) {
	id := in.ID
	if !objectID.MatchString(id) {
		u, err := d.entraObject(ctx, entraUsers, entraIn{ID: id, Fields: []string{"id"}}, nil)
		if err != nil {
			return nil, err
		}
		id, _ = u["id"].(string)
	}
	in.ID = id
	return d.entraObject(ctx, entraKind{path: "/v1.0/reports/authenticationMethods/userRegistrationDetails"}, in, nil)
}

func (d Deps) groupGet(ctx context.Context, in entraIn) (map[string]any, error) {
	out, err := d.entraObject(ctx, entraGroups, in, entraGroups.get)
	if err != nil || len(in.Fields) > 0 {
		return out, err
	}
	path, _ := entraGroups.objectPath(in.ID)
	for key, rel := range map[string]string{"memberCount": "members", "ownerCount": "owners"} {
		var n struct {
			Count int `json:"@odata.count"`
		}
		if err := d.Graph.Object(ctx, path+"/"+rel+"?$count=true&$top=1", graph.Params{Fields: []string{"id"}}, &n); err != nil {
			out[key] = "unavailable: " + err.Error()
			continue
		}
		out[key] = n.Count
	}
	d.addCounterpart(out, func() (*Counterpart, error) { return d.fromEntra(ctx, joinGroup, out) })
	return out, nil
}

const entraListDoc = "Lists page up to 200 at a time with next_cursor. filter is an OData $filter, sort an $orderby, " +
	"fields a $select; query (users and groups only) is a $search on displayName and mail. The server adds ConsistencyLevel and $count when a filter needs them. Read the " +
	"entra://guide/odata-filter resource before writing a filter. Times are RFC 3339 UTC as Graph returns them."

// entraAction is an action of an entraTool and its handler.
type entraAction struct {
	Action
	run func(Deps, context.Context, entraIn) (map[string]any, error)
}

// entraTool is a tool of actions; doc, if set, describes its writes that
// show, or is "" when none does.
func entraTool(name, group, title, desc string, doc func(visible []string) string, actions ...entraAction) Tool {
	t := Tool{Name: name, Group: group}
	for _, a := range actions {
		t.Actions = append(t.Actions, a.Action)
	}
	t.add = func(s *mcp.Server, d Deps, t Tool, visible []string) {
		full := desc
		if doc != nil {
			full += doc(visible)
		}
		addActionTool(s, d, t, &mcp.Tool{Name: name, Title: title, Description: full + "\n\n" + entraListDoc, Annotations: readOnly}, visible,
			func(ctx context.Context, _ *mcp.CallToolRequest, in entraIn) (*mcp.CallToolResult, map[string]any, error) {
				i := slices.IndexFunc(actions, func(a entraAction) bool { return a.Name == in.Action })
				out, err := actions[i].run(d, ctx, in)
				return nil, out, err
			})
	}
	return t
}

// Helpers building entraAction handlers for the common shapes.
func entraSearch(k entraKind) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		return d.entraList(ctx, k, "", in, k.brief)
	}
}

func entraGet(k entraKind) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		return d.entraObject(ctx, k, in, k.get)
	}
}

func related(k entraKind, rel string, def []string) func(Deps, context.Context, entraIn) (map[string]any, error) {
	return func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		return d.entraList(ctx, k, rel, in, def)
	}
}

type entraAPIIn struct {
	ActionParam
	Path   string   `json:"path" jsonschema:"a Graph path starting /v1.0/ or /beta/ (writes: /v1.0/ only, no query string); get may carry its own query string, e.g. /v1.0/users/{id}/memberOf"`
	Filter string   `json:"filter,omitempty" jsonschema:"get: OData $filter; read the entra://guide/odata-filter resource first"`
	Sort   string   `json:"sort,omitempty" jsonschema:"get: OData $orderby"`
	Fields []string `json:"fields,omitempty" jsonschema:"get: $select"`
	Cursor string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call with the same arguments, unchanged"`
	// Not writeIn: its confirm would show for delete, and no raw write takes one.
	Reason string         `json:"reason,omitempty" jsonschema:"writes: why you are making this change; required, and recorded in the audit log"`
	Body   map[string]any `json:"body,omitempty" jsonschema:"writes, post, patch, put: the JSON request body"`
}

const betaWarning = "beta: Microsoft does not support beta APIs in production and may change them without notice"

func (d Deps) apiGet(ctx context.Context, in entraAPIIn) (map[string]any, error) {
	beta := strings.HasPrefix(in.Path, "/beta/")
	if !beta && !strings.HasPrefix(in.Path, "/v1.0/") {
		return nil, errors.New("path must start with /v1.0/ or /beta/")
	}
	page, o, err := d.Graph.Fetch(ctx, in.Path, graph.Params{Filter: in.Filter, Sort: in.Sort, Fields: in.Fields}, in.Cursor)
	if err != nil {
		return nil, err
	}
	out, ok := o.(map[string]any)
	switch {
	case page != nil:
		out = obj(page)
	case !ok:
		out = map[string]any{"value": o}
	}
	if beta {
		out["_unstable"] = betaWarning
	}
	return out, nil
}

var (
	userRead   = []string{"User.Read.All", "Directory.Read.All"}
	groupRead  = []string{"GroupMember.Read.All", "Group.Read.All", "Directory.Read.All"}
	deviceRead = []string{"Device.Read.All", "Directory.Read.All"}
	intuneRead = []string{"DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All"}
)

func init() {
	roster = append(roster,
		entraTool("entra_user", "identity", "Entra ID users",
			"Users of the tenant. search: list users by query (displayName or mail) or filter, as briefs (id, "+
				"userPrincipalName, displayName, mail, accountEnabled, onPremisesSyncEnabled, userType, createdDateTime). "+
				"get: one user by id or UPN, with on-premises sAMAccountName and last sync, jobTitle, department, manager, "+
				"assignedLicenses (with skuPartNumber), lastPasswordChangeDateTime and signInActivity (needs P1; listed in "+
				"_omitted when the tenant lacks it). member_of: the groups, directory roles and administrative units the user "+
				"is a direct member of. devices: the devices the user owns or registered, each with relation. licenses: "+
				"assignedLicenses and licenseAssignmentStates (direct or group-inherited, errors), with skuPartNumber. "+
				"auth_methods: the user's registered authentication methods. registration: the user's MFA and SSPR "+
				"registration details (P1)."+counterpartDoc, entraUserDoc,
			entraAction{Action{Name: "search", Perms: userRead}, entraSearch(entraUsers)},
			entraAction{Action{Name: "get", Perms: userRead}, Deps.userGet},
			entraAction{Action{Name: "member_of", Perms: groupRead}, related(entraUsers, "/memberOf", directoryObjects)},
			entraAction{Action{Name: "devices", Perms: deviceRead}, Deps.userDevices},
			entraAction{Action{Name: "licenses", Perms: userRead}, func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
				out, err := d.entraObject(ctx, entraUsers, in, []string{"id", "userPrincipalName", "assignedLicenses", "licenseAssignmentStates"})
				if err == nil {
					d.nameSkus(ctx, out)
				}
				return out, err
			}},
			entraAction{Action{Name: "auth_methods", Perms: []string{"UserAuthenticationMethod.Read.All"}}, related(entraUsers, "/authentication/methods", nil)},
			entraAction{Action{Name: "registration", Perms: []string{"AuditLog.Read.All"}, Licence: "P1"}, Deps.registration},
			entraAccountState("disable"), entraAccountState("enable"), entraAccountState("revoke_sessions"),
			entraResetPassword, entraIssueTAP, entraDeleteAuthMethod,
		),
		entraTool("entra_group", "identity", "Entra ID groups",
			"Groups of the tenant. search: list groups as briefs (id, displayName, mail, securityEnabled, mailEnabled, "+
				"groupTypes, onPremisesSyncEnabled). get: one group by object id, with description, membershipRule, "+
				"isAssignableToRole, memberCount and ownerCount, but not its members. members: the group's members as "+
				"briefs of their own kind (@odata.type says which); transitive=true lists every nested member instead. "+
				"owners: the group's owners."+counterpartDoc, entraGroupDoc,
			entraAction{Action{Name: "search", Perms: groupRead}, entraSearch(entraGroups)},
			entraAction{Action{Name: "get", Perms: groupRead}, Deps.groupGet},
			entraAction{Action{Name: "members", Perms: groupRead}, func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
				rel := "/members"
				if in.Transitive {
					rel = "/transitiveMembers"
				}
				return d.entraList(ctx, entraGroups, rel, in, directoryObjects)
			}},
			entraAction{Action{Name: "owners", Perms: groupRead}, related(entraGroups, "/owners", directoryObjects)},
			entraMembership("add_members"), entraMembership("remove_members"),
		),
		entraTool("entra_device", "devices", "Entra ID and Intune devices",
			"Devices of the tenant. search: list Entra devices as briefs (id, deviceId, displayName, operatingSystem, "+
				"accountEnabled, trustType, approximateLastSignInDateTime). get: one device by object id (not deviceId), "+
				"with OS version, isCompliant, isManaged, onPremisesSyncEnabled and registeredOwners. owners: the device's "+
				"registered owners. managed_search: Intune managed devices as briefs (id, deviceName, operatingSystem, "+
				"osVersion, complianceState, lastSyncDateTime, userPrincipalName); filter, not query. managed_get: one "+
				"Intune managed device by its Intune id, every property (encryption, ownership, serial number and more). "+
				"Intune is read only here."+counterpartDoc, nil,
			entraAction{Action{Name: "search", Perms: deviceRead}, entraSearch(entraDevices)},
			entraAction{Action{Name: "get", Perms: deviceRead}, func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
				return d.entraGetJoined(ctx, joinDevice, in)
			}},
			entraAction{Action{Name: "owners", Perms: deviceRead}, related(entraDevices, "/registeredOwners", directoryObjects)},
			entraAction{Action{Name: "managed_search", Perms: intuneRead, Licence: "Intune"}, entraSearch(entraManaged)},
			entraAction{Action{Name: "managed_get", Perms: intuneRead, Licence: "Intune"}, entraGet(entraManaged)},
		),
		Tool{Name: "entra_api", Group: "core", Actions: []Action{{Name: "get"}, {Name: "post", Capabilities: entraCapabilities()},
			{Name: "patch", Capabilities: entraCapabilities()}, {Name: "put", Capabilities: entraCapabilities()}, {Name: "delete", Capabilities: entraCapabilities()}},
			add: func(s *mcp.Server, d Deps, t Tool, visible []string) {
				desc := "Raw Graph GET when no entra_* tool fits. get: any path under /v1.0/ or /beta/, as " +
					"Graph returns it; a collection pages like the entra_* lists (200 at a time, next_cursor). " +
					"Beta replies carry _unstable: beta is unsupported in production and changes without notice. " +
					"Read the entra://guide/odata-filter resource before writing a filter."
				if len(visible) > 1 {
					desc += entraAPIWriteDoc
				}
				addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Title: "Raw Microsoft Graph read", Annotations: readOnly, Description: desc},
					visible, func(ctx context.Context, _ *mcp.CallToolRequest, in entraAPIIn) (*mcp.CallToolResult, map[string]any, error) {
						if in.Action != "get" {
							out, err := d.apiWrite(ctx, in)
							return nil, out, err
						}
						out, err := d.apiGet(ctx, in)
						return nil, out, err
					})
			}},
	)
}
