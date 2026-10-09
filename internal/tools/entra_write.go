package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// The Entra write rails, on the framework of write.go. See
// docs/adr/0001-write-capability-map.md.

// entraOp classifies one kind of Graph write: the capability that allows
// it, the first-class action that makes it, and the ad_* action that makes
// it instead when the target is synced from the forest ("" when Entra may
// make it on a synced target).
type entraOp struct {
	method, path string // path under /v1.0; {} is any one segment
	prop         string // a PATCH body property; "" for every other call
	capability   string
	action       string
	synced       string
}

// entraOps classifies Graph writes by method and path, and PATCHes by
// property. Anything not here, nor in the entra-objects allowlist, is
// unmapped: refused.
var entraOps = []entraOp{
	{"PATCH", "users/{}", "accountEnabled", "entra-account-state", "entra_user disable or enable", "ad_user disable or enable"},
	{"POST", "users/{}/revokeSignInSessions", "", "entra-account-state", "entra_user revoke_sessions", ""},
	{"PATCH", "users/{}", "passwordProfile", "entra-credentials", "entra_user reset_password", "ad_user reset_password"},
	{"POST", "users/{}/authentication/temporaryAccessPassMethods", "", "entra-credentials", "entra_user issue_tap", ""},
	{"DELETE", "users/{}/authentication/{}/{}", "", "entra-credentials", "entra_user delete_auth_method", ""},
	{"POST", "groups/{}/members/$ref", "", "entra-group-membership", "entra_group add_members", "ad_group add_members"},
	{"PATCH", "groups/{}", "members@odata.bind", "entra-group-membership", "entra_group add_members", "ad_group add_members"},
	{"DELETE", "groups/{}/members/{}/$ref", "", "entra-group-membership", "entra_group remove_members", "ad_group remove_members"},
	{"POST", "users", "", "entra-objects", "entra_user create", ""},
	{"POST", "groups", "", "entra-objects", "entra_group create", ""},
	{"PUT", "users/{}/manager/$ref", "", "entra-objects", "entra_user set_manager", "ad_api modify"},
	{"DELETE", "users/{}/manager/$ref", "", "entra-objects", "entra_user remove_manager", "ad_api modify"},
	{"DELETE", "users/{}", "", "entra-delete", "entra_user delete", "ad_object delete"},
	{"DELETE", "groups/{}", "", "entra-delete", "entra_group delete", "ad_object delete"},
	{"DELETE", "devices/{}", "", "entra-delete", "entra_device delete", "ad_object delete"},
	{"POST", "directory/deletedItems/{}/restore", "", "entra-delete", "entra_user or entra_group restore", ""},
	{"POST", "users/{}/assignLicense", "", "entra-licenses", "entra_user assign_license or remove_license", ""},
	{"POST", "users/{}/reprocessLicenseAssignment", "", "entra-licenses", "entra_user reprocess_licenses", ""},
	{"PATCH", "devices/{}", "accountEnabled", "entra-devices", "entra_device disable or enable", "ad_computer disable or enable"},
	{"POST", "identityProtection/riskyUsers/dismiss", "", "entra-risk", "entra_risk dismiss", ""},
	{"POST", "identityProtection/riskyUsers/confirmCompromised", "", "entra-risk", "entra_risk confirm_compromised", ""},
	{"POST", "deviceManagement/managedDevices/{}/syncDevice", "", "intune-device-actions", "entra_device sync", ""},
	{"POST", "deviceManagement/managedDevices/{}/rebootNow", "", "intune-device-actions", "entra_device reboot", ""},
	{"POST", "deviceManagement/managedDevices/{}/retire", "", "intune-retire-wipe", "entra_device retire", ""},
	{"POST", "deviceManagement/managedDevices/{}/wipe", "", "intune-retire-wipe", "entra_device wipe", ""},
}

// entraObjectProps is the entra-objects allowlist: by collection, the
// properties entra_api may PATCH. The entra-objects issue fills it.
// ponytail: every listed property is refused on a synced object; that issue
// tells synced properties from cloud ones.
var entraObjectProps = map[string][]string{}

// entraKinds are the collections whose objects a write can target.
var entraKinds = map[string]entraKind{"users": entraUsers, "groups": entraGroups, "devices": entraDevices}

// pathIs reports whether path (under /v1.0) matches pattern.
func pathIs(pattern, path string) bool {
	p, s := strings.Split(pattern, "/"), strings.Split(strings.Trim(path, "/"), "/")
	if len(p) != len(s) {
		return false
	}
	for i := range p {
		if p[i] != "{}" && !strings.EqualFold(p[i], s[i]) {
			return false
		}
	}
	return true
}

// classifyEntra maps one Graph write (method, path under /v1.0, and for a
// PATCH its body's properties) to the operations it makes. raw is
// entra_api, where a write that a first-class action makes is refused and
// pointed to that action.
func classifyEntra(method, path string, props []string, raw bool) ([]entraOp, error) {
	if method != http.MethodPatch {
		props = []string{""}
	}
	if len(props) == 0 {
		return nil, errors.New("a patch needs a body")
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var ops []entraOp
	for _, prop := range props {
		i := slices.IndexFunc(entraOps, func(o entraOp) bool {
			return o.method == method && pathIs(o.path, path) && strings.EqualFold(o.prop, prop)
		})
		switch {
		case i >= 0 && raw:
			o := entraOps[i]
			return nil, fmt.Errorf("entra_api %s %s: call %s instead (the %s capability)", method, path, o.action, o.capability)
		case i >= 0:
			ops = append(ops, entraOps[i])
		case raw && len(segs) == 2 && slices.ContainsFunc(entraObjectProps[segs[0]], func(p string) bool { return strings.EqualFold(p, prop) }):
			ops = append(ops, entraOp{capability: "entra-objects", synced: "ad_api modify"})
		default:
			return nil, fmt.Errorf("%s %s %s is not a write this server makes", method, path, prop)
		}
	}
	return ops, nil
}

// entraWrite is one Entra write: an object of kind, by id, and the call
// made on it (rel under the object, body for the request).
type entraWrite struct {
	tool, action string
	kind         entraKind
	id           string
	in           writeIn
	raw          bool
	method, rel  string
	body         map[string]any
}

// entraWrite runs w through the Entra rails. Every Entra write goes through
// here, so none skips the reason, the capability its call classifies to,
// the pre-read, the protected target and source of authority refusals, or
// the audit log. Nothing is retried.
func (d Deps) entraWrite(ctx context.Context, w entraWrite) (map[string]any, error) {
	reason := strings.TrimSpace(w.in.Reason)
	if reason == "" {
		return nil, errReason
	}
	path, err := w.kind.objectPath(w.id)
	if err != nil {
		return nil, err
	}
	path += w.rel
	endpoint := w.method + " " + path
	audit := []any{"tool", w.tool, "action", w.action, "target", w.id, "endpoint", endpoint, "reason", reason}
	sent := false
	out, err := func() (map[string]any, error) {
		props := slices.Sorted(maps.Keys(w.body))
		ops, err := classifyEntra(w.method, strings.TrimPrefix(path, "/v1.0/"), props, w.raw)
		if err != nil {
			return nil, err
		}
		var caps []string
		for _, o := range ops {
			if !d.Config.Capabilities[o.capability] {
				return nil, fmt.Errorf("%s needs the %s capability, which the operator has not enabled", endpoint, o.capability)
			}
			caps = append(caps, o.capability)
		}
		slices.Sort(caps)
		// Property names only: values (passwords among them) are never logged.
		audit = append(audit, "capability", strings.Join(slices.Compact(caps), ","), "properties", props)
		fields := []string{"id", "displayName", "onPremisesSyncEnabled", "onPremisesSecurityIdentifier"}
		switch w.kind.path {
		case entraUsers.path:
			fields = append(fields, "userPrincipalName")
		case entraGroups.path:
			fields = append(fields, "isAssignableToRole")
		}
		var tgt map[string]any
		if err := d.Graph.Object(ctx, strings.TrimSuffix(path, w.rel), graph.Params{Fields: fields}, &tgt); err != nil {
			return nil, err
		}
		if err := d.entraProtected(ctx, w.kind, tgt); err != nil {
			return nil, err
		}
		if err := d.entraAuthority(ctx, w.kind, tgt, ops); err != nil {
			return nil, err
		}
		d.log().Info("entra write", append(audit, "outcome", "sending")...)
		sent = true
		var body any // a nil map would send null
		if w.body != nil {
			body = w.body
		}
		if err := d.Graph.Do(ctx, w.method, path, body, nil); err != nil {
			return nil, onPremMastered(err)
		}
		upn, _ := tgt["userPrincipalName"].(string)
		name, _ := tgt["displayName"].(string)
		return map[string]any{"id": tgt["id"], "name": cmp.Or(upn, name), "action": w.action, "endpoint": endpoint}, nil
	}()
	if err != nil {
		outcome := "failed"
		if !sent {
			outcome = "not sent"
		}
		d.log().Warn("entra write", append(audit, "outcome", outcome, "error", err.Error())...)
		return nil, err
	}
	d.log().Info("entra write", append(audit, "outcome", "ok")...)
	return out, nil
}

// entraProtected refuses a protected target: a role-assignable group, or a
// user holding a directory role (any role, any scope), in a role-assignable
// group or owning one. A Graph error fails closed.
// ponytail: active assignments only; a PIM-eligible holder passes until it
// activates, and Graph refuses writes on it to a User Administrator.
func (d Deps) entraProtected(ctx context.Context, k entraKind, tgt map[string]any) error {
	id, _ := tgt["id"].(string)
	refuse := func(why string) error {
		return fmt.Errorf("%s is a protected target: it %s. No capability lifts this; an admin makes the change in the Entra admin center", id, why)
	}
	if tgt["isAssignableToRole"] == true {
		return refuse("is a role-assignable group")
	}
	if k.path != entraUsers.path {
		return nil
	}
	p, err := d.Graph.List(ctx, "/v1.0/roleManagement/directory/roleAssignments", graph.Params{
		Filter: "principalId eq '" + strings.ReplaceAll(id, "'", "''") + "'", Fields: []string{"roleDefinitionId", "directoryScopeId"}}, "")
	if err != nil {
		return fmt.Errorf("checking whether %s holds a directory role (needs RoleManagement.Read.Directory): %w", id, err)
	}
	if len(p.Results) > 0 {
		r := p.Results[0]
		return refuse(fmt.Sprintf("holds the directory role %v at scope %v", r["roleDefinitionId"], r["directoryScopeId"]))
	}
	for _, x := range [][2]string{{"/transitiveMemberOf", "is in"}, {"/ownedObjects", "owns"}} {
		rel, how := x[0], x[1]
		for cur := ""; ; {
			p, err := d.Graph.List(ctx, k.path+"/"+id+rel, graph.Params{Fields: []string{"id", "displayName", "isAssignableToRole"}}, cur)
			if err != nil {
				return fmt.Errorf("checking whether %s is a protected target: %w", id, err)
			}
			for _, r := range p.Results {
				switch {
				case r["@odata.type"] == "#microsoft.graph.directoryRole":
					return refuse(fmt.Sprintf("holds the directory role %v", r["displayName"]))
				case r["isAssignableToRole"] == true:
					return refuse(fmt.Sprintf("%s the role-assignable group %v", how, r["displayName"]))
				}
			}
			if cur = p.NextCursor; cur == "" {
				break
			}
		}
	}
	return nil
}

// entraAuthority refuses ops on a target synced from the forest when one
// of them is made in AD instead, naming the AD counterpart and action. A
// Graph or AD error fails closed.
func (d Deps) entraAuthority(ctx context.Context, k entraKind, tgt map[string]any, ops []entraOp) error {
	i := slices.IndexFunc(ops, func(o entraOp) bool { return o.synced != "" })
	joins := []join{joinUser, joinGroup, joinDevice}
	j := slices.IndexFunc(joins, func(j join) bool { return j.entra.path == k.path })
	if i < 0 || j < 0 {
		return nil
	}
	c, err := d.fromEntra(ctx, joins[j], tgt)
	if err != nil {
		return fmt.Errorf("checking the source of authority of %v: %w", tgt["id"], err)
	}
	if c.SourceOfAuthority != "forest" {
		return nil
	}
	return fmt.Errorf("%v is synced from the forest (%s says so): call %s on %s instead", tgt["id"], c.Source, ops[i].synced, cmp.Or(c.ID, "its AD counterpart"))
}

// onPremMastered turns Graph's refusal of a write to a synced object, one
// the source of authority check let through, into what it means.
func onPremMastered(err error) error {
	var ae *graph.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusBadRequest && ae.Code == "Request_BadRequest" && strings.Contains(ae.Message, "on-premises mastered") {
		return fmt.Errorf("the object is owned by the forest (Graph refused the write as on-premises mastered): make the change in AD with the ad_* tools: %w", err)
	}
	return err
}

// entraAccountState is an entra-account-state action of entra_user.
func entraAccountState(action string) entraAction {
	w := entraWrite{tool: "entra_user", action: action, kind: entraUsers, method: http.MethodPatch}
	perms := []string{"User.EnableDisableAccount.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}
	switch action {
	case "disable", "enable":
		w.body = map[string]any{"accountEnabled": action == "enable"}
	case "revoke_sessions":
		w.method, w.rel = http.MethodPost, "/revokeSignInSessions"
		perms = []string{"User.RevokeSessions.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}
	}
	return entraAction{Action{Name: action, Perms: perms, Capabilities: []string{"entra-account-state"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			w := w
			w.id, w.in = in.ID, in.writeIn
			return d.entraWrite(ctx, w)
		}}
}

// entraAccountStateDoc describes the entra-account-state actions that
// show, or is "" when none does.
func entraAccountStateDoc(visible []string) string {
	var says []string
	if slices.Contains(visible, "disable") {
		says = append(says, "disable and enable set accountEnabled")
	}
	if slices.Contains(visible, "revoke_sessions") {
		says = append(says, "revoke_sessions invalidates the user's refresh tokens and session cookies (revokeSignInSessions)")
	}
	if len(says) == 0 {
		return ""
	}
	return "\n\nWrites (the entra-account-state capability), one user by id, with a reason for the audit log: " + strings.Join(says, "; ") +
		". Protected targets (directory role holders, members and owners of role-assignable groups) are refused. On a user synced " +
		"from the forest, disable and enable are refused and name the ad_user action and AD counterpart; revoke_sessions is allowed."
}

// entraCapabilities are the Entra side's capabilities.
func entraCapabilities() []string {
	return slices.DeleteFunc(slices.Clone(config.Capabilities), func(c string) bool { return strings.HasPrefix(c, "ad-") })
}

const entraAPIWriteDoc = "\n\nWrites, one object, under /v1.0/ only, with a reason for the audit log: post, patch, put and delete. " +
	"A write a first-class action makes (accountEnabled, revokeSignInSessions, members, licences, …) is refused and names that " +
	"action; a patch of a property on the entra-objects allowlist is allowed with that capability; every other write, and every " +
	"beta write, is refused. Protected targets and objects synced from the forest are refused, as in every write."

// apiWrite is an entra_api write: a raw call through the same rails as
// every Entra write.
func (d Deps) apiWrite(ctx context.Context, in entraAPIIn) (map[string]any, error) {
	method := strings.ToUpper(in.Action)
	if strings.HasPrefix(in.Path, "/beta/") {
		return nil, errors.New("beta writes are refused: write under /v1.0/ only")
	}
	rest, ok := strings.CutPrefix(in.Path, "/v1.0/")
	if !ok || strings.ContainsAny(rest, "?#") {
		return nil, errors.New("path must start with /v1.0/ and carry no query string")
	}
	var props []string
	if method == http.MethodPatch {
		if props = slices.Sorted(maps.Keys(in.Body)); len(props) == 0 {
			return nil, errors.New("patch needs a body")
		}
	}
	// Only a patch of an allowlisted property of users, groups or devices
	// classifies raw; that write takes the rails, everything else is refused.
	if segs := strings.Split(strings.Trim(rest, "/"), "/"); len(segs) == 2 && method == http.MethodPatch {
		if k, ok := entraKinds[segs[0]]; ok {
			return d.entraWrite(ctx, entraWrite{tool: "entra_api", action: in.Action, kind: k, id: segs[1], in: writeIn{Reason: in.Reason},
				raw: true, method: method, body: in.Body})
		}
	}
	_, err := classifyEntra(method, rest, props, true)
	if err == nil {
		err = fmt.Errorf("%s %s is not a write this server makes", method, rest)
	}
	return nil, err
}
