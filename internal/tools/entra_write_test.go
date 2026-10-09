package tools

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

func TestClassifyEntra(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		props        []string
		raw          bool
		want, synced string // the capability and the ad_* action on a synced target, or what the refusal says
		refused      string
	}{
		{"PATCH", "users/u1", []string{"accountEnabled"}, false, "entra-account-state", "ad_user disable or enable", ""},
		{"POST", "users/u1/revokeSignInSessions", nil, false, "entra-account-state", "", ""},
		// Source of authority per operation: allowed on synced targets, or routed to AD.
		{"POST", "users/u1/assignLicense", nil, false, "entra-licenses", "", ""},
		{"POST", "users/u1/authentication/temporaryAccessPassMethods", nil, false, "entra-credentials", "", ""},
		{"DELETE", "users/u1/authentication/phoneMethods/m1", nil, false, "entra-credentials", "", ""},
		{"POST", "identityProtection/riskyUsers/dismiss", nil, false, "entra-risk", "", ""},
		{"PATCH", "users/u1", []string{"passwordProfile"}, false, "entra-credentials", "ad_user reset_password", ""},
		{"POST", "groups/g1/members/$ref", nil, false, "entra-group-membership", "ad_group add_members", ""},
		{"DELETE", "groups/g1/members/u1/$ref", nil, false, "entra-group-membership", "ad_group remove_members", ""},
		{"DELETE", "users/u1", nil, false, "entra-delete", "ad_object delete", ""},
		{"PATCH", "devices/d1", []string{"accountEnabled"}, false, "entra-devices", "ad_computer disable or enable", ""},
		// Raw: a first-class write is routed to its action.
		{"PATCH", "users/u1", []string{"accountEnabled"}, true, "", "", "call entra_user disable or enable instead (the entra-account-state capability)"},
		{"POST", "Users/u1/revokeSignInSessions/", nil, true, "", "", "call entra_user revoke_sessions instead"},
		{"POST", "groups/g1/members/$ref", nil, true, "", "", "call entra_group add_members instead"},
		{"DELETE", "users/u1", nil, true, "", "", "call entra_user delete instead"},
		{"POST", "deviceManagement/managedDevices/m1/wipe", nil, true, "", "", "call entra_device wipe instead"},
		{"PATCH", "users/u1", []string{"jobTitle", "accountEnabled"}, true, "", "", "call entra_user disable or enable instead"},
		// Raw: the entra-objects allowlist, by collection, and nothing else.
		{"PATCH", "users/u1", []string{"jobTitle"}, true, "entra-objects", "ad_object edit", ""},
		{"PATCH", "users/u1", []string{"usageLocation"}, true, "entra-objects", "", ""}, // cloud-only: allowed on synced
		{"PATCH", "groups/g1", []string{"description"}, true, "entra-objects", "ad_object edit", ""},
		{"PATCH", "groups/g1", []string{"jobTitle"}, true, "", "", "not a write this server makes"},
		{"PATCH", "users/u1", []string{"mail"}, true, "", "", "not a write this server makes"},
		{"PATCH", "groups/g1", []string{"isAssignableToRole"}, true, "", "", "not a write this server makes"},
		{"PATCH", "users/u1", []string{"jobTitle"}, false, "", "", "not a write this server makes"},
		{"PATCH", "users/u1", nil, false, "", "", "a patch needs a body"},
		{"PATCH", "users/u1/manager", []string{"jobTitle"}, true, "", "", "not a write this server makes"},
		{"POST", "roleManagement/directory/roleAssignments", nil, true, "", "", "not a write this server makes"},
	} {
		ops, err := classifyEntra(tc.method, tc.path, tc.props, tc.raw)
		var caps, synced []string
		for _, o := range ops {
			caps, synced = append(caps, o.capability), append(synced, o.synced)
		}
		got := strings.Join(slices.Compact(caps), ",")
		if tc.refused == "" && (err != nil || got != tc.want || strings.Join(slices.Compact(synced), ",") != tc.synced) ||
			tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)) {
			t.Errorf("%s %s %v raw=%v: %q %q %v", tc.method, tc.path, tc.props, tc.raw, got, synced, err)
		}
	}
}

// Users the stub knows: u1 cloud-only, u2 synced, u3 a directory role
// holder by membership, u4 in a role-assignable group, u5 owning one, u6
// assigned a custom role scoped to an admin unit.
const (
	u1 = "00000000-0000-0000-0000-000000000001"
	u2 = "00000000-0000-0000-0000-000000000002"
	u3 = "00000000-0000-0000-0000-000000000003"
	u4 = "00000000-0000-0000-0000-000000000004"
	u5 = "00000000-0000-0000-0000-000000000005"
	u6 = "00000000-0000-0000-0000-000000000006"
)

// Groups the stub knows: g1 cloud-only, g2 synced, g3 role-assignable; m1
// an authentication method of every user.
const (
	g1 = "00000000-0000-0000-0000-0000000000a1"
	g2 = "00000000-0000-0000-0000-0000000000a2"
	g3 = "00000000-0000-0000-0000-0000000000a3"
	m1 = "00000000-0000-0000-0000-0000000000b1"
	// sp1 is a service principal holding a directory role.
	sp1 = "00000000-0000-0000-0000-0000000000c1"
	// dv1 is a cloud device, dv2 a synced one.
	dv1 = "00000000-0000-0000-0000-0000000000e1"
	dv2 = "00000000-0000-0000-0000-0000000000e2"
)

// entraWriteStub answers the pre-reads of the users and groups above, the
// users' memberships and ownerships, and every write with write.
func entraWriteStub(write string) func(*http.Request) string {
	return func(r *http.Request) string {
		p := r.URL.Path
		id := path.Base(path.Dir(p))
		switch {
		case r.Method != http.MethodGet:
			return write
		case strings.HasSuffix(p, "/onPremisesSyncBehavior"):
			return "403"
		case strings.HasSuffix(p, "/roleAssignments") && (strings.Contains(r.URL.Query().Get("$filter"), u6) || strings.Contains(r.URL.Query().Get("$filter"), sp1)):
			return `{"value":[{"roleDefinitionId":"00000000-0000-0000-0000-0000000000d1","directoryScopeId":"/administrativeUnits/au1"}]}`
		case strings.HasSuffix(p, "/roleAssignments"):
			return `{"value":[]}`
		case strings.HasSuffix(p, "/transitiveMemberOf") && id == u3:
			return `{"value":[{"@odata.type":"#microsoft.graph.group","id":"g0"},{"@odata.type":"#microsoft.graph.directoryRole","id":"r1","displayName":"Helpdesk Administrator"}]}`
		case strings.HasSuffix(p, "/transitiveMemberOf") && id == u4, strings.HasSuffix(p, "/ownedObjects") && id == u5:
			return `{"value":[{"@odata.type":"#microsoft.graph.group","id":"g1","displayName":"tier0","isAssignableToRole":true}]}`
		case strings.HasSuffix(p, "/transitiveMemberOf"), strings.HasSuffix(p, "/ownedObjects"):
			return `{"value":[{"@odata.type":"#microsoft.graph.group","id":"g0","displayName":"staff","isAssignableToRole":false}]}`
		case strings.HasSuffix(p, "/authentication/methods/"+m1):
			return `{"@odata.type":"#microsoft.graph.phoneAuthenticationMethod","id":"` + m1 + `"}`
		case strings.HasPrefix(p, "/v1.0/directoryObjects/") && path.Base(p) == sp1:
			return `{"@odata.type":"#microsoft.graph.servicePrincipal","id":"` + sp1 + `"}`
		case strings.HasPrefix(p, "/v1.0/directoryObjects/"):
			return `{"@odata.type":"#microsoft.graph.user","id":"` + path.Base(p) + `"}`
		case path.Base(p) == g1:
			return `{"id":"` + g1 + `","displayName":"staff"}`
		case path.Base(p) == dv1:
			return `{"id":"` + dv1 + `","displayName":"pc1"}`
		case path.Base(p) == dv2:
			return `{"id":"` + dv2 + `","displayName":"pc2","onPremisesSyncEnabled":true,"onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-1107"}`
		case path.Base(p) == g2:
			return `{"id":"` + g2 + `","displayName":"synced","onPremisesSyncEnabled":true,"onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-1106"}`
		case path.Base(p) == g3:
			return `{"@odata.type":"#microsoft.graph.group","id":"` + g3 + `","displayName":"tier0","isAssignableToRole":true}`
		case path.Base(p) == u2:
			return `{"id":"` + u2 + `","userPrincipalName":"u2@example.com","onPremisesSyncEnabled":true,"onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-1105"}`
		case strings.Contains(p, "/deletedItems/"):
			return `{"@odata.type":"#microsoft.graph.user","id":"` + path.Base(p) + `","userPrincipalName":"gone@example.com"}`
		}
		return `{"id":"` + path.Base(p) + `","userPrincipalName":"user@example.com"}`
	}
}

// entraWriteDeps is Deps with the Entra side against entraWriteStub(write),
// capabilities caps and the audit log in buf, and the writes the stub saw.
func entraWriteDeps(t *testing.T, write string, caps ...string) (Deps, *bytes.Buffer, func() []string) {
	t.Helper()
	g, seen := graphStub(t, entraWriteStub(write))
	c := map[string]bool{}
	for _, x := range caps {
		c[x] = true
	}
	buf := &bytes.Buffer{}
	writes := func() []string {
		var out []string
		for _, r := range seen() {
			if r.Method != http.MethodGet {
				out = append(out, r.Method+" "+r.URL.Path)
			}
		}
		return out
	}
	return Deps{Config: &config.Config{Capabilities: c}, Graph: g, Log: slog.New(slog.NewTextHandler(buf, nil))}, buf, writes
}

func entraRun(d Deps, action, id, reason string) (map[string]any, error) {
	return entraAccountState(action).run(d, context.Background(), entraIn{ID: id, writeIn: writeIn{Reason: reason}})
}

// Disable sends one PATCH of accountEnabled, and the audit log has the
// reason, target, capability, endpoint and outcome.
func TestEntraDisableWrites(t *testing.T) {
	var body []byte
	g, seen := graphStub(t, func(r *http.Request) string {
		if r.Method == http.MethodPatch {
			body, _ = io.ReadAll(r.Body)
		}
		return entraWriteStub("")(r)
	})
	d, buf, _ := entraWriteDeps(t, "", "entra-account-state")
	d.Graph = g // this stub also keeps the body
	out, err := entraRun(d, "disable", u1, " ticket 42 ")
	if err != nil {
		t.Fatal(err)
	}
	if out["id"] != u1 || out["action"] != "disable" {
		t.Errorf("reply %v", out)
	}
	if n := len(seen()); string(body) != `{"accountEnabled":false}` || seen()[n-1].Method != http.MethodPatch {
		t.Errorf("wrote %s, last %s", body, seen()[n-1].Method)
	}
	log := buf.String()
	for _, want := range []string{`reason="ticket 42"`, "target=" + u1, "capability=entra-account-state",
		`endpoint="PATCH /v1.0/users/` + u1 + `"`, "outcome=sending", "outcome=ok", "properties=[accountEnabled]"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log lacks %s:\n%s", want, log)
		}
	}
}

// Everything that refuses an Entra write refuses before sending.
func TestEntraWriteRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps []string
		w    func(Deps) (map[string]any, error)
		says string
	}{
		{"no reason", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "disable", u1, " ") }, "reason is required"},
		{"capability off", []string{"entra-licenses"}, func(d Deps) (map[string]any, error) { return entraRun(d, "enable", u1, "r") },
			"needs the entra-account-state capability"},
		{"bad id", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "enable", "x", "r") }, "want an object id"},
		{"synced", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "disable", u2, "r") },
			"synced from the forest (onPremisesSyncEnabled says so): call ad_user disable or enable"},
		{"role holder", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "revoke_sessions", u3, "r") },
			"protected target: it holds the directory role Helpdesk Administrator"},
		{"role-assignable member", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "disable", u4, "r") },
			"protected target: it is in the role-assignable group tier0"},
		{"role-assignable owner", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "disable", u5, "r") },
			"protected target: it owns the role-assignable group tier0"},
		{"custom role", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) { return entraRun(d, "disable", u6, "r") },
			"protected target: it holds the directory role 00000000-0000-0000-0000-0000000000d1 at scope /administrativeUnits/au1"},
		{"raw beta", []string{"entra-objects"}, func(d Deps) (map[string]any, error) {
			return d.apiWrite(context.Background(), entraAPIIn{ActionParam: ActionParam{"patch"}, Path: "/beta/users/" + u1, Reason: "r", Body: map[string]any{"jobTitle": "x"}})
		}, "beta writes are refused"},
		{"raw routed", []string{"entra-account-state"}, func(d Deps) (map[string]any, error) {
			return d.apiWrite(context.Background(), entraAPIIn{ActionParam: ActionParam{"patch"}, Path: "/v1.0/users/" + u1, Reason: "r", Body: map[string]any{"accountEnabled": false}})
		}, "call entra_user disable or enable instead"},
		{"raw unmapped", []string{"entra-objects"}, func(d Deps) (map[string]any, error) {
			return d.apiWrite(context.Background(), entraAPIIn{ActionParam: ActionParam{"post"}, Path: "/v1.0/roleManagement/directory/roleAssignments", Reason: "r"})
		}, "not a write this server makes"},
		{"raw unlisted property", []string{"entra-objects"}, func(d Deps) (map[string]any, error) {
			return d.apiWrite(context.Background(), entraAPIIn{ActionParam: ActionParam{"patch"}, Path: "/v1.0/users/" + u1, Reason: "r", Body: map[string]any{"mail": "x@example.com"}})
		}, "not a write this server makes"},
	} {
		d, _, writes := entraWriteDeps(t, "", tc.caps...)
		_, err := tc.w(d)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if w := writes(); len(w) != 0 {
			t.Errorf("%s: sent %v", tc.name, w)
		}
	}
}

// Revoking sessions is allowed on a synced user.
func TestEntraRevokeSynced(t *testing.T) {
	d, _, writes := entraWriteDeps(t, `{"value":true}`, "entra-account-state")
	if _, err := entraRun(d, "revoke_sessions", u2, "r"); err != nil {
		t.Fatal(err)
	}
	if w := writes(); !slices.Equal(w, []string{"POST /v1.0/users/" + u2 + "/revokeSignInSessions"}) {
		t.Errorf("wrote %v", w)
	}
}

// Graph's on-premises mastered refusal says the forest owns the object; a
// 429 is not retried.
func TestEntraWriteErrors(t *testing.T) {
	for write, want := range map[string]string{
		"400 Request_BadRequest Unable to update the specified properties for on-premises mastered Directory Sync objects": "owned by the forest",
		"429": "HTTP 429",
	} {
		d, buf, writes := entraWriteDeps(t, write, "entra-account-state")
		_, err := entraRun(d, "enable", u1, "r")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", write, err)
		}
		if n := len(writes()); n != 1 {
			t.Errorf("%s: sent %d times", write, n)
		}
		if !strings.Contains(buf.String(), "outcome=failed") {
			t.Errorf("%s: audit log %s", write, buf.String())
		}
	}
}

// With entra-account-state on, entra_user shows its writes and reason,
// entra_api its write methods; a missing permission hides a write.
func TestEntraAccountStateRegisters(t *testing.T) {
	cs, _ := entraSession(t, nil, func(*http.Request) string { return `{}` }, "entra-account-state")
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"entra_user": {"search", "get", "member_of", "devices", "licenses", "auth_methods", "registration", "disable", "enable", "revoke_sessions"},
		"entra_api":  {"get", "post", "patch", "put", "delete"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: %v, want %v", name, got[name], want)
		}
	}
	if p := props(t, cs, "entra_user"); !slices.Contains(p, "reason") || slices.Contains(p, "confirm") {
		t.Errorf("entra_user: %v", p)
	}
	if p := props(t, cs, "entra_api"); !slices.Contains(p, "reason") || !slices.Contains(p, "body") {
		t.Errorf("entra_api: %v", p)
	}
	if p := props(t, cs, "entra_group"); slices.Contains(p, "reason") {
		t.Errorf("entra_group, with no write, has reason: %v", p)
	}
	cs, _ = entraSession(t, &graph.Probe{Roles: []string{"User.Read.All", "User.RevokeSessions.All"}}, func(*http.Request) string { return `{}` }, "entra-account-state")
	if got := listed(t, cs)["entra_user"]; !slices.Equal(got[len(got)-1:], []string{"revoke_sessions"}) || slices.Contains(got, "disable") {
		t.Errorf("entra_user with only User.RevokeSessions.All: %v", got)
	}
}

// entraBodies is d with its Graph stub keeping each write's body too.
func entraBodies(t *testing.T, d Deps, write string) (Deps, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	d.Graph, _ = graphStub(t, func(r *http.Request) string {
		if r.Method != http.MethodGet {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, r.Method+" "+r.URL.Path+" "+string(b))
			mu.Unlock()
		}
		return entraWriteStub(write)(r)
	})
	return d, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(bodies) }
}

func entraCall(d Deps, a entraAction, in entraIn) (map[string]any, error) {
	if in.Reason == "" {
		in.Reason = "r"
	}
	return a.run(d, context.Background(), in)
}

// A reset sets the generated password, returned once and never logged,
// must-change by default; confirm names the UPN. On a synced user it is
// refused, and routed to AD, unless writeback is declared on.
func TestEntraResetPassword(t *testing.T) {
	d, buf, _ := entraWriteDeps(t, "", "entra-credentials")
	d, bodies := entraBodies(t, d, "")
	out, err := entraCall(d, entraResetPassword, entraIn{ID: u1, writeIn: writeIn{Confirm: "User@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := out["password"].(string)
	want := `PATCH /v1.0/users/` + u1 + ` {"passwordProfile":{"forceChangePasswordNextSignIn":true,"password":"` + pw + `"}}`
	if len(pw) < 20 || out["must_change"] != true || !slices.Equal(bodies(), []string{want}) {
		t.Errorf("reply %v, wrote %v", out, bodies())
	}
	if strings.Contains(buf.String(), pw) || !strings.Contains(buf.String(), "properties=[passwordProfile]") {
		t.Errorf("audit log:\n%s", buf.String())
	}
	no := false
	if _, err := entraCall(d, entraResetPassword, entraIn{ID: u1, MustChange: &no, writeIn: writeIn{Confirm: "user@example.com"}}); err != nil ||
		!strings.Contains(bodies()[1], `"forceChangePasswordNextSignIn":false`) {
		t.Errorf("must_change false: %v %v", err, bodies())
	}

	for _, tc := range []struct {
		name, id, confirm, writeback, says string
	}{
		{"confirm mismatch", u1, "other@example.com", "", `confirm must be the target's userPrincipalName: ` + u1 + ` is "user@example.com"`},
		{"synced", u2, "u2@example.com", "unknown", "call ad_user reset_password on its AD counterpart instead; Entra resets a synced user's password only when the operator declares password writeback on"},
		{"synced, writeback off", u2, "u2@example.com", "off", "call ad_user reset_password"},
		{"synced, writeback on", u2, "u2@example.com", "on", ""},
	} {
		d, _, writes := entraWriteDeps(t, "", "entra-credentials")
		d.Config.Entra = &config.Entra{PasswordWriteback: tc.writeback}
		_, err := entraCall(d, entraResetPassword, entraIn{ID: tc.id, writeIn: writeIn{Confirm: tc.confirm}})
		if tc.says == "" && (err != nil || len(writes()) != 1) || tc.says != "" && (err == nil || !strings.Contains(err.Error(), tc.says) || len(writes()) != 0) {
			t.Errorf("%s: %v, wrote %v", tc.name, err, writes())
		}
	}
}

// A TAP is in the reply and never in the log.
func TestEntraIssueTAP(t *testing.T) {
	d, buf, writes := entraWriteDeps(t, `{"id":"t1","temporaryAccessPass":"TAPsecret123","lifetimeInMinutes":60}`, "entra-credentials")
	out, err := entraCall(d, entraIssueTAP, entraIn{ID: u2}) // allowed on a synced user
	if err != nil {
		t.Fatal(err)
	}
	if tap, _ := out["temporary_access_pass"].(map[string]any); tap["temporaryAccessPass"] != "TAPsecret123" {
		t.Errorf("reply %v", out)
	}
	if w := writes(); !slices.Equal(w, []string{"POST /v1.0/users/" + u2 + "/authentication/temporaryAccessPassMethods"}) {
		t.Errorf("wrote %v", w)
	}
	if log := buf.String(); strings.Contains(log, "TAPsecret123") || !strings.Contains(log, "outcome=ok") {
		t.Errorf("audit log:\n%s", log)
	}
}

// An auth method is deleted from the collection of its type.
func TestEntraDeleteAuthMethod(t *testing.T) {
	d, _, writes := entraWriteDeps(t, "", "entra-credentials")
	if _, err := entraCall(d, entraDeleteAuthMethod, entraIn{ID: u1, MethodID: m1}); err != nil {
		t.Fatal(err)
	}
	if w := writes(); !slices.Equal(w, []string{"DELETE /v1.0/users/" + u1 + "/authentication/phoneMethods/" + m1}) {
		t.Errorf("wrote %v", w)
	}
	if _, err := entraCall(d, entraDeleteAuthMethod, entraIn{ID: u1, MethodID: "a/b"}); err == nil || !strings.Contains(err.Error(), "want an authentication method id") {
		t.Errorf("bad method id: %v", err)
	}
}

// Members are added in one bind PATCH and removed one $ref each, one
// already out being done; protected and synced groups and protected
// members are refused before anything is sent.
func TestEntraMembership(t *testing.T) {
	d, _, _ := entraWriteDeps(t, "", "entra-group-membership")
	d, bodies := entraBodies(t, d, "")
	out, err := entraCall(d, entraMembership("add_members"), entraIn{ID: g1, Members: []string{u2, u1, u1}})
	if err != nil {
		t.Fatal(err)
	}
	ref := d.Graph.URL("/v1.0/directoryObjects/")
	if want := `PATCH /v1.0/groups/` + g1 + ` {"members@odata.bind":["` + ref + u1 + `","` + ref + u2 + `"]}`; !slices.Equal(bodies(), []string{want}) {
		t.Errorf("wrote %v, want %s", bodies(), want)
	}
	if !slices.Equal(out["members"].([]string), []string{u1, u2}) {
		t.Errorf("reply %v", out)
	}
	d, _, writes := entraWriteDeps(t, "404", "entra-group-membership")
	if _, err := entraCall(d, entraMembership("remove_members"), entraIn{ID: g1, Members: []string{u1, u2}}); err != nil {
		t.Fatal(err)
	}
	if w := writes(); !slices.Equal(w, []string{"DELETE /v1.0/groups/" + g1 + "/members/" + u1 + "/$ref", "DELETE /v1.0/groups/" + g1 + "/members/" + u2 + "/$ref"}) {
		t.Errorf("wrote %v", w)
	}

	many := make([]string, 21)
	for i := range many {
		many[i] = u1
	}
	for _, tc := range []struct {
		name, action, group string
		members             []string
		says                string
	}{
		{"role-assignable", "add_members", g3, []string{u1}, "protected target: it is a role-assignable group"},
		{"synced", "remove_members", g2, []string{u1}, "synced from the forest (onPremisesSyncEnabled says so): call ad_group remove_members"},
		{"protected member", "add_members", g1, []string{u1, u3}, "member " + u3 + " is a protected target: it holds the directory role Helpdesk Administrator"},
		{"role-holding service principal", "add_members", g1, []string{sp1}, "member " + sp1 + " is a protected target: it holds the directory role"},
		{"too many", "add_members", g1, many, "takes 1 to 20 members, got 21"},
		{"none", "remove_members", g1, nil, "takes 1 to 20 members, got 0"},
		{"not a GUID", "add_members", g1, []string{"user@example.com"}, "want an object id"},
	} {
		d, _, writes := entraWriteDeps(t, "", "entra-group-membership")
		_, err := entraCall(d, entraMembership(tc.action), entraIn{ID: tc.group, Members: tc.members})
		if err == nil || !strings.Contains(err.Error(), tc.says) || len(writes()) != 0 {
			t.Errorf("%s: %v, wrote %v", tc.name, err, writes())
		}
	}
}

// With entra-credentials and entra-group-membership on, their actions and
// parameters show.
func TestEntraCredentialsRegister(t *testing.T) {
	cs, _ := entraSession(t, nil, func(*http.Request) string { return `{}` }, "entra-credentials", "entra-group-membership")
	got := listed(t, cs)
	if want := []string{"reset_password", "issue_tap", "delete_auth_method"}; !slices.Equal(got["entra_user"][len(got["entra_user"])-3:], want) || slices.Contains(got["entra_user"], "disable") {
		t.Errorf("entra_user: %v", got["entra_user"])
	}
	if want := []string{"search", "get", "members", "owners", "add_members", "remove_members"}; !slices.Equal(got["entra_group"], want) {
		t.Errorf("entra_group: %v", got["entra_group"])
	}
	for _, want := range []string{"reason", "confirm", "must_change", "method_id"} {
		if !slices.Contains(props(t, cs, "entra_user"), want) {
			t.Errorf("entra_user lacks %s", want)
		}
	}
	if p := props(t, cs, "entra_group"); !slices.Contains(p, "members") || !slices.Contains(p, "reason") || slices.Contains(p, "confirm") {
		t.Errorf("entra_group: %v", p)
	}
}

// Create sends one POST of the object with allowlisted properties: a user
// enabled, with a generated password it must change, returned once and
// never logged; a group a security group, never role-assignable.
func TestEntraCreate(t *testing.T) {
	d, buf, _ := entraWriteDeps(t, `{"id":"`+u1+`"}`, "entra-objects")
	d, bodies := entraBodies(t, d, `{"id":"`+u1+`"}`)
	out, err := entraCall(d, entraCreate(entraUsers), entraIn{Name: "New User", UPN: "new.user@example.com",
		Properties: map[string]string{"jobTitle": "Engineer", "department": ""}})
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := out["password"].(string)
	want := `POST /v1.0/users {"accountEnabled":true,"displayName":"New User","jobTitle":"Engineer","mailNickname":"new.user",` +
		`"passwordProfile":{"forceChangePasswordNextSignIn":true,"password":"` + pw + `"},"userPrincipalName":"new.user@example.com"}`
	if len(pw) < 20 || out["id"] != u1 || out["must_change"] != true || !slices.Equal(bodies(), []string{want}) {
		t.Errorf("reply %v, wrote %v", out, bodies())
	}
	if log := buf.String(); strings.Contains(log, pw) || !strings.Contains(log, "capability=entra-objects") || !strings.Contains(log, "outcome=ok") {
		t.Errorf("audit log:\n%s", log)
	}
	if _, err := entraCall(d, entraCreate(entraGroups), entraIn{Name: "Team (EU) #1", Properties: map[string]string{"description": "d"}}); err != nil {
		t.Fatal(err)
	}
	if want := `POST /v1.0/groups {"description":"d","displayName":"Team (EU) #1","mailEnabled":false,"mailNickname":"TeamEU1","securityEnabled":true}`; bodies()[1] != want {
		t.Errorf("wrote %s, want %s", bodies()[1], want)
	}

	for _, tc := range []struct {
		name string
		caps []string
		k    entraKind
		in   entraIn
		says string
	}{
		{"no reason", []string{"entra-objects"}, entraUsers, entraIn{Name: "n", UPN: "n@example.com", writeIn: writeIn{Reason: " "}}, "reason is required"},
		{"capability off", []string{"entra-delete"}, entraUsers, entraIn{Name: "n", UPN: "n@example.com"}, "needs the entra-objects capability"},
		{"no upn", []string{"entra-objects"}, entraUsers, entraIn{Name: "n"}, "create needs upn"},
		{"no name", []string{"entra-objects"}, entraGroups, entraIn{}, "create needs name"},
		{"role-assignable", []string{"entra-objects"}, entraGroups, entraIn{Name: "n", Properties: map[string]string{"isAssignableToRole": "true"}},
			"isAssignableToRole is not a property this server sets on groups"},
		{"not allowlisted", []string{"entra-objects"}, entraUsers, entraIn{Name: "n", UPN: "n@example.com", Properties: map[string]string{"mobilePhone": "1"}},
			"mobilePhone is not a property this server sets on users"},
	} {
		d, _, writes := entraWriteDeps(t, "", tc.caps...)
		_, err := entraCall(d, entraCreate(tc.k), tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.says) || len(writes()) != 0 {
			t.Errorf("%s: %v, wrote %v", tc.name, err, writes())
		}
	}
}

// Edit patches allowlisted properties, an empty value clearing one; on a
// synced object only the cloud-only ones. The manager is set by reference.
func TestEntraEdit(t *testing.T) {
	d, _, _ := entraWriteDeps(t, "", "entra-objects")
	d, bodies := entraBodies(t, d, "")
	if _, err := entraCall(d, entraEdit(entraUsers), entraIn{ID: u1, Properties: map[string]string{"jobTitle": "x", "department": ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err := entraCall(d, entraEdit(entraUsers), entraIn{ID: u2, Properties: map[string]string{"usageLocation": "US"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := entraCall(d, entraManager("set_manager"), entraIn{ID: u1, Manager: u5}); err != nil {
		t.Fatal(err)
	}
	if _, err := entraCall(d, entraManager("remove_manager"), entraIn{ID: u1}); err != nil {
		t.Fatal(err)
	}
	ref := d.Graph.URL("/v1.0/users/")
	if want := []string{
		`PATCH /v1.0/users/` + u1 + ` {"department":null,"jobTitle":"x"}`,
		`PATCH /v1.0/users/` + u2 + ` {"usageLocation":"US"}`,
		`PUT /v1.0/users/` + u1 + `/manager/$ref {"@odata.id":"` + ref + u5 + `"}`,
		`DELETE /v1.0/users/` + u1 + `/manager/$ref `,
	}; !slices.Equal(bodies(), want) {
		t.Errorf("wrote %q, want %q", bodies(), want)
	}

	for _, tc := range []struct {
		name string
		a    entraAction
		in   entraIn
		says string
	}{
		{"synced property", entraEdit(entraUsers), entraIn{ID: u2, Properties: map[string]string{"jobTitle": "x"}},
			"synced from the forest (onPremisesSyncEnabled says so): call ad_object edit"},
		{"synced group", entraEdit(entraGroups), entraIn{ID: g2, Properties: map[string]string{"description": "x"}}, "call ad_object edit"},
		{"first-class property", entraEdit(entraUsers), entraIn{ID: u1, Properties: map[string]string{"accountEnabled": "false"}},
			"call entra_user disable or enable instead"},
		{"not allowlisted", entraEdit(entraUsers), entraIn{ID: u1, Properties: map[string]string{"mail": "x@example.com"}}, "not a write this server makes"},
		{"none", entraEdit(entraUsers), entraIn{ID: u1}, "edit needs properties"},
		{"clear displayName", entraEdit(entraUsers), entraIn{ID: u1, Properties: map[string]string{"displayName": ""}}, "displayName can't be cleared"},
		{"protected", entraEdit(entraUsers), entraIn{ID: u3, Properties: map[string]string{"jobTitle": "x"}}, "protected target"},
		{"synced manager", entraManager("set_manager"), entraIn{ID: u2, Manager: u1}, "call ad_object edit"},
		{"manager not a GUID", entraManager("set_manager"), entraIn{ID: u1, Manager: "boss@example.com"}, "want the manager's object id"},
	} {
		d, _, writes := entraWriteDeps(t, "", "entra-objects")
		_, err := entraCall(d, tc.a, tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.says) || len(writes()) != 0 {
			t.Errorf("%s: %v, wrote %v", tc.name, err, writes())
		}
	}
}

// Delete needs confirm, the user's UPN or a group's or device's
// displayName; synced objects are refused and routed to AD. Restore posts
// to deletedItems, refusing a deleted protected target.
func TestEntraDeleteRestore(t *testing.T) {
	d, _, writes := entraWriteDeps(t, "", "entra-delete")
	for _, c := range []struct {
		a       entraAction
		id      string
		confirm string
	}{
		{entraDelete(entraUsers), u1, "User@example.com"},
		{entraDelete(entraGroups), g1, "staff"},
		{entraDelete(entraDevices), dv1, "pc1"},
		{entraRestore(entraUsers), u1, ""},
	} {
		if _, err := entraCall(d, c.a, entraIn{ID: c.id, writeIn: writeIn{Confirm: c.confirm}}); err != nil {
			t.Fatalf("%s %s: %v", c.a.Name, c.id, err)
		}
	}
	if want := []string{"DELETE /v1.0/users/" + u1, "DELETE /v1.0/groups/" + g1, "DELETE /v1.0/devices/" + dv1,
		"POST /v1.0/directory/deletedItems/" + u1 + "/restore"}; !slices.Equal(writes(), want) {
		t.Errorf("wrote %v, want %v", writes(), want)
	}

	for _, tc := range []struct {
		name string
		a    entraAction
		in   entraIn
		says string
	}{
		{"no confirm", entraDelete(entraUsers), entraIn{ID: u1}, `confirm must be the target's userPrincipalName: ` + u1 + ` is "user@example.com"`},
		{"group confirm", entraDelete(entraGroups), entraIn{ID: g1, writeIn: writeIn{Confirm: "user@example.com"}}, `confirm must be the target's displayName: ` + g1 + ` is "staff"`},
		{"synced user", entraDelete(entraUsers), entraIn{ID: u2, writeIn: writeIn{Confirm: "u2@example.com"}}, "call ad_object delete"},
		{"synced device", entraDelete(entraDevices), entraIn{ID: dv2, writeIn: writeIn{Confirm: "pc2"}}, "call ad_object delete"},
		{"protected", entraDelete(entraGroups), entraIn{ID: g3, writeIn: writeIn{Confirm: "tier0"}}, "protected target: it is a role-assignable group"},
		{"deleted role-assignable group", entraRestore(entraGroups), entraIn{ID: g3}, "protected target: it is a role-assignable group"},
		{"deleted role holder", entraRestore(entraUsers), entraIn{ID: u6}, "protected target: it holds the directory role"},
		{"restore of another kind", entraRestore(entraGroups), entraIn{ID: u1}, "is a #microsoft.graph.user, not a group"},
	} {
		d, _, writes := entraWriteDeps(t, "", "entra-delete")
		_, err := entraCall(d, tc.a, tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.says) || len(writes()) != 0 {
			t.Errorf("%s: %v, wrote %v", tc.name, err, writes())
		}
	}
}

// With entra-objects and entra-delete on, their actions and parameters show.
func TestEntraObjectsRegister(t *testing.T) {
	cs, _ := entraSession(t, nil, func(*http.Request) string { return `{}` }, "entra-objects", "entra-delete")
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"entra_user":   {"create", "edit", "set_manager", "remove_manager", "delete", "restore"},
		"entra_group":  {"create", "edit", "delete", "restore"},
		"entra_device": {"delete"},
	} {
		if g := got[name]; len(g) < len(want) || !slices.Equal(g[len(g)-len(want):], want) {
			t.Errorf("%s: %v, want it to end %v", name, g, want)
		}
	}
	for _, want := range []string{"reason", "confirm", "name", "upn", "properties", "manager"} {
		if !slices.Contains(props(t, cs, "entra_user"), want) {
			t.Errorf("entra_user lacks %s", want)
		}
	}
	if p := props(t, cs, "entra_device"); !slices.Contains(p, "confirm") || slices.Contains(p, "properties") {
		t.Errorf("entra_device: %v", p)
	}
}
