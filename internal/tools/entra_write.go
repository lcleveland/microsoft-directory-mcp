package tools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
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
	{"PUT", "users/{}/manager/$ref", "", "entra-objects", "entra_user set_manager", "ad_object edit"},
	{"DELETE", "users/{}/manager/$ref", "", "entra-objects", "entra_user remove_manager", "ad_object edit"},
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
// properties create, edit and entra_api may set. Descriptive ones only, as
// in AD: nothing that signs anyone in, routes mail, changes a phone (a
// sensitive action) or makes a group role-assignable.
var entraObjectProps = map[string][]string{
	"users": {"displayName", "givenName", "surname", "jobTitle", "department", "companyName", "officeLocation",
		"streetAddress", "city", "state", "postalCode", "country", "employeeId", "employeeType", "usageLocation"},
	"groups": {"displayName", "description"},
}

// entraCloudProps are the allowlisted properties sync never writes, so
// Entra may set them on a synced object; sync writes every other one.
var entraCloudProps = []string{"usageLocation"}

// entraKinds are the collections whose objects a write can target.
var entraKinds = map[string]entraKind{"users": entraUsers, "groups": entraGroups, "devices": entraDevices}

// entraDeleted is directory/deletedItems: deleted users and groups, kept 30 days.
var entraDeleted = entraKind{path: "/v1.0/directory/deletedItems"}

// hasFold reports whether list holds s, ignoring case.
func hasFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, s) })
}

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
			return nil, fmt.Errorf("%s %s: call %s instead (the %s capability)", method, path, o.action, o.capability)
		case i >= 0:
			ops = append(ops, entraOps[i])
		case raw && len(segs) == 2 && hasFold(entraObjectProps[segs[0]], prop):
			o := entraOp{capability: "entra-objects", synced: "ad_object edit"}
			if hasFold(entraCloudProps, prop) {
				o.synced = ""
			}
			ops = append(ops, o)
		default:
			return nil, fmt.Errorf("%s %s %s is not a write this server makes", method, path, prop)
		}
	}
	return ops, nil
}

// entraWrite is one Entra write: an object of kind, by id, and the calls
// made on it (method on each of rels under the object, with body).
type entraWrite struct {
	tool, action string
	kind         entraKind
	id           string
	in           writeIn
	raw          bool
	confirm      bool // in.Confirm must be the target's userPrincipalName, or displayName
	method       string
	rels         []string // none: the object itself
	at           string   // the one call's path in place of rels, when it is not under the object
	body         map[string]any
	check        func(context.Context) error // more refusals, after the target's
	reply        any                         // decodes the last call's reply
	typ          string                      // the target's @odata.type must be this, when set
}

// entraWrite runs w through the Entra rails. Every Entra write to an
// existing object goes through here (create, with none, is entraCreate),
// so none skips the reason, the capability its call classifies to,
// the pre-read, the protected target and source of authority refusals, or
// the audit log. Nothing is retried.
func (d Deps) entraWrite(ctx context.Context, w entraWrite) (map[string]any, error) {
	reason := strings.TrimSpace(w.in.Reason)
	if reason == "" {
		return nil, errReason
	}
	base, err := w.kind.objectPath(w.id)
	if err != nil {
		return nil, err
	}
	rels := w.rels
	if len(rels) == 0 {
		rels = []string{""}
	}
	var paths []string
	for _, rel := range rels {
		paths = append(paths, base+rel)
	}
	if w.at != "" {
		paths = []string{w.at}
	}
	endpoint := w.method + " " + strings.Join(paths, ", ")
	audit := []any{"tool", w.tool, "action", w.action, "target", w.id, "endpoint", endpoint, "reason", reason}
	sent := false
	out, err := func() (map[string]any, error) {
		props := slices.Sorted(maps.Keys(w.body))
		var ops []entraOp
		for _, path := range paths {
			o, err := classifyEntra(w.method, strings.TrimPrefix(path, "/v1.0/"), props, w.raw)
			if err != nil {
				return nil, err
			}
			ops = append(ops, o...)
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
		case entraDeleted.path:
			fields = nil // a deleted object of any type: all of it
		case entraManaged.path:
			fields = []string{"id", "deviceName"}
		}
		var tgt map[string]any
		if err := d.Graph.Object(ctx, base, graph.Params{Fields: fields}, &tgt); err != nil {
			return nil, err
		}
		upn, _ := tgt["userPrincipalName"].(string)
		name, _ := tgt["displayName"].(string)
		if n, ok := tgt["deviceName"].(string); ok {
			name = n
		}
		if w.confirm && !strings.EqualFold(strings.TrimSpace(w.in.Confirm), cmp.Or(upn, name)) {
			what := cmp.Or(map[string]string{entraUsers.path: "userPrincipalName", entraManaged.path: "deviceName"}[w.kind.path], "displayName")
			return nil, fmt.Errorf("confirm must be the target's %s: %v is %q. Check it is the object you mean, then retry", what, tgt["id"], cmp.Or(upn, name))
		}
		if w.typ != "" && tgt["@odata.type"] != w.typ {
			return nil, fmt.Errorf("%v is a %v, not a %s: call the tool of its kind", tgt["id"], tgt["@odata.type"], strings.TrimPrefix(w.typ, "#microsoft.graph."))
		}
		if err := d.entraProtected(ctx, w.kind, tgt); err != nil {
			return nil, err
		}
		if err := d.entraAuthority(ctx, w.kind, tgt, ops); err != nil {
			return nil, err
		}
		if w.check != nil {
			if err := w.check(ctx); err != nil {
				return nil, err
			}
		}
		d.log().Info("entra write", append(audit, "outcome", "sending")...)
		sent = true
		var body any // a nil map would send null
		if w.body != nil {
			body = w.body
		}
		for i, path := range paths {
			err := d.Graph.Do(ctx, w.method, path, body, w.reply)
			var ae *graph.APIError
			if w.method == http.MethodDelete && strings.HasSuffix(path, "/$ref") && errors.As(err, &ae) && ae.Status == http.StatusNotFound {
				continue // the reference is already gone
			}
			if err != nil && i > 0 {
				err = fmt.Errorf("%d of %d calls made (%s), then: %w", i, len(paths), strings.Join(rels[:i], ", "), err)
			}
			if err != nil {
				return nil, onPremMastered(err)
			}
		}
		return map[string]any{"id": tgt["id"], "name": cmp.Or(upn, name), "action": w.action, "endpoint": endpoint}, nil
	}()
	if err != nil {
		outcome := "failed"
		if !sent {
			outcome = "not sent"
		}
		d.log().Warn("entra write", append(audit, "outcome", outcome, "error", err.Error())...)
		return nil, audited{err}
	}
	d.log().Info("entra write", append(audit, "outcome", "ok")...)
	return out, nil
}

// entraProtected refuses a protected target: a role-assignable group, or a
// user or service principal holding a directory role (any role, any scope), in a role-assignable
// group or owning one, or owning any application or service principal (whatever it holds: its
// owner can add a credential and sign in as it). A Graph error fails closed.
// ponytail: active assignments only; a PIM-eligible holder passes until it
// activates, and Graph refuses writes on it to a User Administrator.
// ponytail: a deleted user's memberships and ownerships can't be read, so
// its restore checks role assignments only; Graph refuses restoring a role
// holder to a User Administrator.
func (d Deps) entraProtected(ctx context.Context, k entraKind, tgt map[string]any) error {
	id, _ := tgt["id"].(string)
	refuse := func(why string) error {
		return fmt.Errorf("%s is a protected target: it %s. No capability lifts this; an admin makes the change in the Entra admin center", id, why)
	}
	if tgt["isAssignableToRole"] == true {
		return refuse("is a role-assignable group")
	}
	if k.path != entraUsers.path && k.path != entraSPs.path && tgt["@odata.type"] != entraUsers.typ {
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
	if k.path == entraDeleted.path {
		return nil
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
				case rel == "/ownedObjects" && (r["@odata.type"] == "#microsoft.graph.application" || r["@odata.type"] == entraSPs.typ):
					return refuse(fmt.Sprintf("owns the %s %v", strings.TrimPrefix(r["@odata.type"].(string), "#microsoft.graph."), r["displayName"]))
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
// of them is made in AD instead, naming the AD counterpart and action; a
// password reset is made in Entra when the operator declares writeback on.
// A Graph or AD error fails closed.
func (d Deps) entraAuthority(ctx context.Context, k entraKind, tgt map[string]any, ops []entraOp) error {
	writeback := d.Config.Entra != nil && d.Config.Entra.PasswordWriteback == "on"
	i := slices.IndexFunc(ops, func(o entraOp) bool { return o.synced != "" && !(writeback && o.prop == "passwordProfile") })
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
	err = fmt.Errorf("%v is synced from the forest (%s says so): call %s on %s instead", tgt["id"], c.Source, ops[i].synced, cmp.Or(c.ID, "its AD counterpart"))
	if ops[i].prop == "passwordProfile" {
		err = fmt.Errorf("%w; Entra resets a synced user's password only when the operator declares password writeback on (--entra-password-writeback)", err)
	}
	return err
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
		w.method, w.rels = http.MethodPost, []string{"/revokeSignInSessions"}
		perms = []string{"User.RevokeSessions.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}
	}
	return entraAction{Action{Name: action, Perms: perms, AlsoPerms: roleRead, Capabilities: []string{"entra-account-state"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			w := w
			w.id, w.in = in.ID, in.writeIn
			return d.entraWrite(ctx, w)
		}}
}

// entraResetPassword is entra_user reset_password (entra-credentials): a
// generated password set through passwordProfile, must-change unless
// turned off, with confirm. The reply is the one place it appears.
// ponytail: the password avoids only a UPN id's name, not the displayName;
// a synced user's AD complexity check may refuse one in about a thousand.
// ponytail: with writeback declared on, a synced user's reset is this same
// app-only PATCH; docs/research/hybrid-sync.md §5 documents writeback for
// the delegated resetPassword. If Graph refuses it as on-premises mastered,
// onPremMastered says so; move to resetPassword once delegated auth exists.
var entraResetPassword = entraAction{Action{Name: "reset_password", Capabilities: []string{"entra-credentials"},
	Perms: []string{"User-PasswordProfile.ReadWrite.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}, AlsoPerms: roleRead},
	func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		must := in.MustChange == nil || *in.MustChange
		name, _, _ := strings.Cut(in.ID, "@")
		pw := newPassword(0, name)
		out, err := d.entraWrite(ctx, entraWrite{tool: "entra_user", action: "reset_password", kind: entraUsers, id: in.ID, in: in.writeIn,
			confirm: true, method: http.MethodPatch,
			body: map[string]any{"passwordProfile": map[string]any{"password": string(pw), "forceChangePasswordNextSignIn": must}}})
		if err != nil {
			return nil, lostReset(err)
		}
		out["password"], out["must_change"] = string(pw), must
		return out, nil
	}}

// entraIssueTAP is entra_user issue_tap (entra-credentials): a Temporary
// Access Pass with the tenant policy's defaults. The reply is the one
// place it appears.
var entraIssueTAP = entraAction{Action{Name: "issue_tap", Capabilities: []string{"entra-credentials"},
	Perms: []string{"UserAuthMethod-TAP.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All"}, AlsoPerms: roleRead},
	func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		var tap map[string]any
		out, err := d.entraWrite(ctx, entraWrite{tool: "entra_user", action: "issue_tap", kind: entraUsers, id: in.ID, in: in.writeIn,
			method: http.MethodPost, rels: []string{"/authentication/temporaryAccessPassMethods"}, body: map[string]any{}, reply: &tap})
		if err != nil {
			return nil, err
		}
		out["temporary_access_pass"] = tap
		return out, nil
	}}

// entraDeleteAuthMethod is entra_user delete_auth_method
// (entra-credentials): one of the user's authentication methods, by id,
// deleted from the collection of its type.
var entraDeleteAuthMethod = entraAction{Action{Name: "delete_auth_method", Capabilities: []string{"entra-credentials"},
	Perms: []string{"UserAuthenticationMethod.ReadWrite.All"}, AlsoPerms: roleRead},
	func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
		// The reason first, as in entraWrite: no read for a write that can't be made.
		if strings.TrimSpace(in.Reason) == "" {
			return nil, errReason
		}
		// Not only GUIDs: FIDO2 and Windows Hello ids are base64url.
		if in.MethodID == "" || strings.ContainsAny(in.MethodID, "/?#%\\") {
			return nil, fmt.Errorf("method_id %q: want an authentication method id from auth_methods", in.MethodID)
		}
		path, err := entraUsers.objectPath(in.ID)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := d.Graph.Object(ctx, path+"/authentication/methods/"+url.PathEscape(in.MethodID), graph.Params{}, &m); err != nil {
			return nil, err
		}
		// #microsoft.graph.fido2AuthenticationMethod is in fido2Methods, and so on.
		typ, _ := m["@odata.type"].(string)
		kind, ok := strings.CutSuffix(strings.TrimPrefix(typ, "#microsoft.graph."), "AuthenticationMethod")
		if !ok || kind == "" || kind == "password" {
			return nil, fmt.Errorf("method %s has type %q, not an authentication method this server deletes (a password is reset, not deleted)", in.MethodID, typ)
		}
		out, err := d.entraWrite(ctx, entraWrite{tool: "entra_user", action: "delete_auth_method", kind: entraUsers, id: in.ID, in: in.writeIn,
			method: http.MethodDelete, rels: []string{"/authentication/" + kind + "Methods/" + url.PathEscape(in.MethodID)}})
		if err != nil {
			return nil, err
		}
		out["method"] = map[string]any{"id": in.MethodID, "@odata.type": typ}
		return out, nil
	}}

// entraMembership is entra_group add_members (one members@odata.bind
// PATCH) or remove_members (one $ref delete each; one already out is
// done), entra-group-membership. A protected member is refused, as a
// protected group is.
func entraMembership(action string) entraAction {
	return entraAction{Action{Name: action, Capabilities: []string{"entra-group-membership"},
		Perms: []string{"GroupMember.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All"}, AlsoPerms: roleRead},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			if n := len(in.Members); n == 0 || n > maxMembers {
				return nil, fmt.Errorf("%s takes 1 to %d members, got %d: call again for more", action, maxMembers, n)
			}
			ids := slices.Compact(slices.Sorted(slices.Values(in.Members)))
			for _, id := range ids {
				if !objectID.MatchString(id) {
					return nil, fmt.Errorf("member %q: want an object id (GUID)", id)
				}
			}
			w := entraWrite{tool: "entra_group", action: action, kind: entraGroups, id: in.ID, in: in.writeIn,
				check: func(ctx context.Context) error {
					for _, id := range ids {
						var m map[string]any
						if err := d.Graph.Object(ctx, "/v1.0/directoryObjects/"+id, graph.Params{}, &m); err != nil {
							return fmt.Errorf("member %s: %w", id, err)
						}
						k := entraKind{}
						for _, x := range []entraKind{entraUsers, entraSPs} {
							if m["@odata.type"] == x.typ {
								k = x
							}
						}
						if err := d.entraProtected(ctx, k, m); err != nil {
							return fmt.Errorf("member %w", err)
						}
					}
					return nil
				}}
			if action == "add_members" {
				var refs []string
				for _, id := range ids {
					refs = append(refs, d.Graph.URL("/v1.0/directoryObjects/"+id))
				}
				w.method, w.body = http.MethodPatch, map[string]any{"members@odata.bind": refs}
			} else {
				w.method = http.MethodDelete
				for _, id := range ids {
					w.rels = append(w.rels, "/members/"+id+"/$ref")
				}
			}
			out, err := d.entraWrite(ctx, w)
			if err != nil {
				return nil, err
			}
			out["members"] = ids
			return out, nil
		}}
}

// entraLicense is entra_user assign_license or remove_license (one
// assignLicense call of 1 to 20 SKUs) or reprocess_licenses
// (reprocessLicenseAssignment), entra-licenses. Allowed on synced users.
func entraLicense(action string) entraAction {
	return entraAction{Action{Name: action, Capabilities: []string{"entra-licenses"},
		Perms: []string{"LicenseAssignment.ReadWrite.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}, AlsoPerms: roleRead},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			w := entraWrite{tool: "entra_user", action: action, kind: entraUsers, id: in.ID, in: in.writeIn, method: http.MethodPost}
			if action == "reprocess_licenses" {
				w.rels, w.body = []string{"/reprocessLicenseAssignment"}, map[string]any{}
				return d.entraWrite(ctx, w)
			}
			if n := len(in.Skus); n == 0 || n > maxMembers {
				return nil, fmt.Errorf("%s takes 1 to %d skus, got %d: call again for more", action, maxMembers, n)
			}
			add, remove := []any{}, []string{}
			for _, s := range in.Skus {
				if !objectID.MatchString(s) {
					return nil, fmt.Errorf("sku %q: want a skuId (GUID), from entra_license skus", s)
				}
				if action == "assign_license" {
					add = append(add, map[string]any{"skuId": s, "disabledPlans": []string{}})
				} else {
					remove = append(remove, s)
				}
			}
			w.rels, w.body = []string{"/assignLicense"}, map[string]any{"addLicenses": add, "removeLicenses": remove}
			out, err := d.entraWrite(ctx, w)
			if err != nil {
				return nil, err
			}
			out["skus"] = in.Skus
			return out, nil
		}}
}

// entraDeviceState is entra_device disable or enable (entra-devices).
func entraDeviceState(action string) entraAction {
	return entraAction{Action{Name: action, Perms: []string{"Device.ReadWrite.All", "Directory.ReadWrite.All"}, Capabilities: []string{"entra-devices"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			return d.entraWrite(ctx, entraWrite{tool: "entra_device", action: action, kind: entraDevices, id: in.ID, in: in.writeIn,
				method: http.MethodPatch, body: map[string]any{"accountEnabled": action == "enable"}})
		}}
}

// intuneAction is entra_device sync or reboot (intune-device-actions), or
// retire or wipe (intune-retire-wipe) with confirm: one POST to an Intune
// managed device, with no options. Intune
// accepts the action and the device carries it out later, so the reply
// says it was dispatched, not done.
func intuneAction(action string) entraAction {
	op := map[string]string{"sync": "syncDevice", "reboot": "rebootNow", "retire": "retire", "wipe": "wipe"}[action]
	capability, confirm := "intune-device-actions", false
	if action == "retire" || action == "wipe" {
		capability, confirm = "intune-retire-wipe", true
	}
	return entraAction{Action{Name: action, Perms: []string{"DeviceManagementManagedDevices.PrivilegedOperations.All"}, AlsoPerms: intuneRead, Licence: "Intune", Capabilities: []string{capability}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			w := entraWrite{tool: "entra_device", action: action, kind: entraManaged, id: in.ID, in: in.writeIn, confirm: confirm,
				method: http.MethodPost, rels: []string{"/" + op}}
			if action == "wipe" {
				w.body = map[string]any{} // Graph's defaults: no keepEnrollmentData and the like
			}
			out, err := d.entraWrite(ctx, w)
			if err != nil {
				return nil, err
			}
			out["dispatched"] = "Intune accepted the action; the device carries it out at its next check-in. Check managed_get, and do not repeat the call"
			return out, nil
		}}
}

// entraRiskAction is entra_risk dismiss or confirm_compromised
// (entra-risk): one risky user, by object id. Allowed on synced users.
func entraRiskAction(action string) entraAction {
	op := map[string]string{"dismiss": "dismiss", "confirm_compromised": "confirmCompromised"}[action]
	return entraAction{Action{Name: action, Perms: []string{"IdentityRiskyUser.ReadWrite.All"}, AlsoPerms: roleRead, Licence: "P2", Capabilities: []string{"entra-risk"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			if !objectID.MatchString(in.ID) {
				return nil, fmt.Errorf("id %q: want the user's object id (GUID), from risky_users", in.ID)
			}
			return d.entraWrite(ctx, entraWrite{tool: "entra_risk", action: action, kind: entraUsers, id: in.ID, in: in.writeIn,
				method: http.MethodPost, at: "/v1.0/identityProtection/riskyUsers/" + op, body: map[string]any{"userIds": []string{in.ID}}})
		}}
}

// entraCreate is entra_user or entra_group create (entra-objects): one
// cloud object in one POST, with allowlisted properties. A user gets a
// generated password, returned once, which it must change, and is enabled;
// a group is a security group, never mail-enabled or role-assignable.
// Never retried, like every write.
func entraCreate(k entraKind) entraAction {
	tool, col := "entra_group", "groups"
	perms := []string{"Group.Create", "Group.ReadWrite.All", "Directory.ReadWrite.All"}
	if k.path == entraUsers.path {
		tool, col, perms = "entra_user", "users", []string{"User.ReadWrite.All", "Directory.ReadWrite.All"}
	}
	return entraAction{Action{Name: "create", Perms: perms, Capabilities: []string{"entra-objects"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			reason := strings.TrimSpace(in.Reason)
			if reason == "" {
				return nil, errReason
			}
			endpoint := "POST " + k.path
			audit := []any{"tool", tool, "action", "create", "target", cmp.Or(in.UPN, in.Name), "endpoint", endpoint, "reason", reason}
			body := map[string]any{"displayName": in.Name}
			var pw secret
			err := func() error {
				if in.Name == "" {
					return errors.New("create needs name, the new object's displayName")
				}
				if k.path == entraUsers.path {
					nick, _, ok := strings.Cut(in.UPN, "@")
					if !ok || nick == "" {
						return errors.New("create needs upn, the new user's userPrincipalName")
					}
					pw = newPassword(0, nick, in.Name)
					body["userPrincipalName"], body["mailNickname"], body["accountEnabled"] = in.UPN, nick, true
					body["passwordProfile"] = map[string]any{"password": string(pw), "forceChangePasswordNextSignIn": true}
				} else {
					body["mailNickname"], body["mailEnabled"], body["securityEnabled"] = mailNickname(in.Name), false, true
				}
				for p, v := range in.Properties {
					if !hasFold(entraObjectProps[col], p) {
						return fmt.Errorf("%s is not a property this server sets on %s; it sets %s", p, col, strings.Join(entraObjectProps[col], ", "))
					}
					if v != "" {
						body[p] = v
					}
				}
				ops, err := classifyEntra(http.MethodPost, col, nil, false)
				if err == nil && !d.Config.Capabilities[ops[0].capability] {
					err = fmt.Errorf("%s needs the %s capability, which the operator has not enabled", endpoint, ops[0].capability)
				}
				return err
			}()
			// Property names only: values (passwords among them) are never logged.
			audit = append(audit, "capability", "entra-objects", "properties", slices.Sorted(maps.Keys(body)))
			if err != nil {
				d.log().Warn("entra write", append(audit, "outcome", "not sent", "error", err.Error())...)
				return nil, audited{err}
			}
			d.log().Info("entra write", append(audit, "outcome", "sending")...)
			var made map[string]any
			if err := d.Graph.Do(ctx, http.MethodPost, k.path, body, &made); err != nil {
				d.log().Warn("entra write", append(audit, "outcome", "failed", "error", err.Error())...)
				return nil, audited{err}
			}
			d.log().Info("entra write", append(audit, "outcome", "ok", "id", made["id"])...)
			out := map[string]any{"id": made["id"], "name": cmp.Or(in.UPN, in.Name), "action": "create", "endpoint": endpoint}
			if pw != "" {
				out["password"], out["must_change"] = string(pw), true
			}
			return out, nil
		}}
}

// mailNickname is a group's mailNickname from its name: the characters
// Graph takes, or "group" when none is left.
// ponytail: not unique; a security group's needn't be.
func mailNickname(name string) string {
	nick := strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return r
		}
		return -1
	}, name)
	return cmp.Or(nick[:min(len(nick), 64)], "group") // Graph takes up to 64
}

// entraEdit is entra_user or entra_group edit (entra-objects): allowlisted
// properties of one object set in one PATCH, an empty value clearing one.
// On a synced object only those sync never writes are allowed.
func entraEdit(k entraKind) entraAction {
	tool, perms, also := "entra_group", []string{"Group.ReadWrite.All", "Directory.ReadWrite.All"}, []string(nil)
	if k.path == entraUsers.path {
		tool, perms, also = "entra_user", []string{"User.ReadWrite.All", "Directory.ReadWrite.All"}, roleRead
	}
	return entraAction{Action{Name: "edit", Perms: perms, AlsoPerms: also, Capabilities: []string{"entra-objects"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			if len(in.Properties) == 0 {
				return nil, errors.New("edit needs properties")
			}
			body := map[string]any{}
			for p, v := range in.Properties {
				body[p] = v
				if v == "" && strings.EqualFold(p, "displayName") {
					return nil, errors.New("displayName can't be cleared, only changed")
				}
				if v == "" {
					body[p] = nil
				}
			}
			return d.entraWrite(ctx, entraWrite{tool: tool, action: "edit", kind: k, id: in.ID, in: in.writeIn, raw: true,
				method: http.MethodPatch, body: body})
		}}
}

// entraManager is entra_user set_manager or remove_manager (entra-objects).
func entraManager(action string) entraAction {
	return entraAction{Action{Name: action, Perms: []string{"User.ReadWrite.All", "Directory.ReadWrite.All"}, AlsoPerms: roleRead, Capabilities: []string{"entra-objects"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			w := entraWrite{tool: "entra_user", action: action, kind: entraUsers, id: in.ID, in: in.writeIn,
				method: http.MethodDelete, rels: []string{"/manager/$ref"}}
			if action == "set_manager" {
				if !objectID.MatchString(in.Manager) {
					return nil, fmt.Errorf("manager %q: want the manager's object id (GUID)", in.Manager)
				}
				w.method, w.body = http.MethodPut, map[string]any{"@odata.id": d.Graph.URL("/v1.0/users/" + in.Manager)}
			}
			out, err := d.entraWrite(ctx, w)
			if err != nil {
				return nil, err
			}
			out["manager"] = in.Manager
			return out, nil
		}}
}

// entraDelete is the delete action (entra-delete) of the entra_* tool of
// k: one object, with confirm.
func entraDelete(k entraKind) entraAction {
	tool, perms, also := "entra_user", []string{"User.DeleteRestore.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}, roleRead
	switch k.path {
	case entraGroups.path:
		tool, perms, also = "entra_group", []string{"Group.ReadWrite.All", "Directory.ReadWrite.All"}, nil
	case entraDevices.path:
		tool, perms, also = "entra_device", []string{"Device.ReadWrite.All", "Directory.ReadWrite.All"}, nil
	}
	return entraAction{Action{Name: "delete", Perms: perms, AlsoPerms: also, Capabilities: []string{"entra-delete"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			return d.entraWrite(ctx, entraWrite{tool: tool, action: "delete", kind: k, id: in.ID, in: in.writeIn, confirm: true, method: http.MethodDelete})
		}}
}

// entraRestore is entra_user or entra_group restore (entra-delete): one
// deleted object, by its id, from directory/deletedItems.
func entraRestore(k entraKind) entraAction {
	tool, perms, also := "entra_group", []string{"Group.ReadWrite.All", "Directory.ReadWrite.All"}, []string(nil)
	if k.path == entraUsers.path {
		tool, perms, also = "entra_user", []string{"User.DeleteRestore.All", "User.ReadWrite.All", "Directory.ReadWrite.All"}, roleRead
	}
	return entraAction{Action{Name: "restore", Perms: perms, AlsoPerms: also, Capabilities: []string{"entra-delete"}},
		func(d Deps, ctx context.Context, in entraIn) (map[string]any, error) {
			return d.entraWrite(ctx, entraWrite{tool: tool, action: "restore", kind: entraDeleted, id: in.ID, in: in.writeIn,
				method: http.MethodPost, rels: []string{"/restore"}, typ: k.typ})
		}}
}

// entraObjectsDoc describes the entra-objects and entra-delete actions of
// the tool for col that show.
func entraObjectsDoc(col string, visible []string) []string {
	var says []string
	if slices.Contains(visible, "create") {
		what := "a security group (never mail-enabled or role-assignable) named name"
		if col == "users" {
			what = "a cloud user named name with upn, enabled, with a password the server generates, returned once in the reply and " +
				"never logged, which the user must change at next sign-in"
		}
		says = append(says, "create makes "+what+"; never retried, so on a lost reply search before trying again (entra-objects)")
	}
	if slices.Contains(visible, "edit") {
		says = append(says, "edit sets properties (an empty value clears one), only these: "+strings.Join(entraObjectProps[col], ", ")+
			"; create may set them too (entra-objects)")
	}
	if slices.Contains(visible, "set_manager") {
		says = append(says, "set_manager sets the user's manager to manager, remove_manager removes it (entra-objects)")
	}
	if slices.Contains(visible, "delete") {
		kept := "kept 30 days in deleted items"
		if col == "groups" {
			kept = "a security group for good, a Microsoft 365 group kept 30 days in deleted items"
		}
		says = append(says, "delete deletes it, with confirm: "+kept+" (entra-delete)")
	}
	if slices.Contains(visible, "restore") {
		says = append(says, "restore brings back a deleted one by its id, from entra_api get /v1.0/directory/deletedItems/microsoft.graph."+
			strings.TrimSuffix(col, "s")+" (entra-delete)")
	}
	return says
}

// entraGroupDoc describes the entra_group writes that show, or is "" when
// none does.
func entraGroupDoc(visible []string) string {
	var says []string
	if slices.Contains(visible, "add_members") {
		says = append(says, "add_members and remove_members take members, 1 to 20 object ids (users, groups, devices). An add is one call: if any "+
			"member is already in, Graph refuses it whole. A remove of one already out is no error. Protected members (directory role holders, "+
			"members and owners of role-assignable groups, owners of applications and service principals) are refused (entra-group-membership)")
	}
	says = append(says, entraObjectsDoc("groups", visible)...)
	if len(says) == 0 {
		return ""
	}
	return "\n\nWrites, one group by object id (create: none), with a reason for the audit log: " + strings.Join(says, "; ") +
		". Role-assignable groups are refused; on a group synced from the forest, every write but restore is refused and names " +
		"the ad_* action and AD counterpart."
}

// entraDeviceDoc describes the entra_device writes that show, or is "" when
// none does.
func entraDeviceDoc(visible []string) string {
	var says []string
	if slices.Contains(visible, "disable") {
		says = append(says, "disable and enable set accountEnabled (entra-devices)")
	}
	if slices.Contains(visible, "delete") {
		says = append(says, "delete deletes it, with confirm (its displayName); a deleted device can't be restored, and a synced one names ad_object delete (entra-delete)")
	}
	doc := ""
	if len(says) > 0 {
		doc = "\n\nWrites, one Entra device by object id, with a reason for the audit log: " + strings.Join(says, "; ") +
			". A device synced from the forest is refused and names the ad_* action and AD counterpart."
	}
	var intune []string
	if slices.Contains(visible, "sync") {
		intune = append(intune, "sync makes it check in with Intune now, reboot restarts it (intune-device-actions)")
	}
	if slices.Contains(visible, "retire") {
		intune = append(intune, "retire removes company data and management, wipe resets it to factory settings with Graph's defaults; "+
			"each needs confirm, its deviceName (intune-retire-wipe)")
	}
	if len(intune) > 0 {
		doc += "\n\nIntune actions, one managed device by its Intune id (from managed_search), with a reason for the audit log: " +
			strings.Join(intune, "; ") + ". An action is dispatched, not done: the reply says Intune accepted it and the device acts " +
			"at its next check-in. Never repeat a call because the action has not shown yet; nothing is retried."
	}
	return doc
}

// entraRiskDoc describes the entra_risk writes when they show.
func entraRiskDoc(visible []string) string {
	if !slices.Contains(visible, "dismiss") && !slices.Contains(visible, "confirm_compromised") {
		return ""
	}
	return "\n\nWrites (the entra-risk capability), one user by object id (id from risky_users), with a reason for the audit log: " +
		"dismiss dismisses the user's risk; confirm_compromised marks the user compromised, raising risk to high so risk policies act. " +
		"Allowed on users synced from the forest; protected targets (directory role holders, members and owners of role-assignable groups, owners of applications and service principals) are refused."
}

// entraUserDoc describes the entra_user writes that show, or is "" when
// none does.
func entraUserDoc(visible []string) string {
	var says []string
	if slices.Contains(visible, "disable") {
		says = append(says, "disable and enable set accountEnabled (entra-account-state)")
	}
	if slices.Contains(visible, "revoke_sessions") {
		says = append(says, "revoke_sessions invalidates the user's refresh tokens and session cookies (revokeSignInSessions, entra-account-state)")
	}
	if slices.Contains(visible, "reset_password") {
		says = append(says, "reset_password sets a password the server generates, returned once in the reply and never logged, "+
			"which the user must change at next sign-in unless must_change is false; confirm must be the user's userPrincipalName (entra-credentials)")
	}
	if slices.Contains(visible, "issue_tap") {
		says = append(says, "issue_tap issues a Temporary Access Pass with the tenant policy's lifetime, returned once in the reply and never logged (entra-credentials)")
	}
	if slices.Contains(visible, "delete_auth_method") {
		says = append(says, "delete_auth_method deletes one authentication method by method_id, from auth_methods (entra-credentials)")
	}
	says = append(says, entraObjectsDoc("users", visible)...)
	if slices.Contains(visible, "assign_license") {
		says = append(says, "assign_license and remove_license assign or remove skus, 1 to 20 skuIds from entra_license skus, in one call "+
			"(assigning needs the user's usageLocation set); reprocess_licenses reprocesses group-based licences (entra-licenses)")
	}
	if len(says) == 0 {
		return ""
	}
	return "\n\nWrites, one user by id (create: none), with a reason for the audit log: " + strings.Join(says, "; ") +
		". Protected targets (directory role holders, members and owners of role-assignable groups, owners of applications and service principals) are refused. On a user synced " +
		"from the forest, disable, enable, edit (but for " + strings.Join(entraCloudProps, ", ") + "), set_manager, remove_manager and delete " +
		"are refused and name the ad_* action and AD counterpart, and so is reset_password unless the operator declares password " +
		"writeback on; the rest are allowed."
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
	// A patch on a user, group or device takes the rails, where only an
	// allowlisted user or group property classifies; everything else is refused.
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
