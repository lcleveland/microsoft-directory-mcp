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
	"testing"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

func TestClassifyEntra(t *testing.T) {
	old := entraObjectProps
	entraObjectProps = map[string][]string{"users": {"jobTitle"}}
	t.Cleanup(func() { entraObjectProps = old })
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
		{"PATCH", "users/u1", []string{"jobTitle"}, true, "entra-objects", "ad_api modify", ""},
		{"PATCH", "groups/g1", []string{"jobTitle"}, true, "", "", "not a write this server makes"},
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

// entraWriteStub answers the pre-reads of the users above and their
// memberships and ownerships, and every write with write.
func entraWriteStub(write string) func(*http.Request) string {
	return func(r *http.Request) string {
		p := r.URL.Path
		id := path.Base(path.Dir(p))
		switch {
		case r.Method != http.MethodGet:
			return write
		case strings.HasSuffix(p, "/onPremisesSyncBehavior"):
			return "403"
		case strings.HasSuffix(p, "/roleAssignments") && strings.Contains(r.URL.Query().Get("$filter"), u6):
			return `{"value":[{"roleDefinitionId":"00000000-0000-0000-0000-0000000000d1","directoryScopeId":"/administrativeUnits/au1"}]}`
		case strings.HasSuffix(p, "/roleAssignments"):
			return `{"value":[]}`
		case strings.HasSuffix(p, "/transitiveMemberOf") && id == u3:
			return `{"value":[{"@odata.type":"#microsoft.graph.group","id":"g0"},{"@odata.type":"#microsoft.graph.directoryRole","id":"r1","displayName":"Helpdesk Administrator"}]}`
		case strings.HasSuffix(p, "/transitiveMemberOf") && id == u4, strings.HasSuffix(p, "/ownedObjects") && id == u5:
			return `{"value":[{"@odata.type":"#microsoft.graph.group","id":"g1","displayName":"tier0","isAssignableToRole":true}]}`
		case strings.HasSuffix(p, "/transitiveMemberOf"), strings.HasSuffix(p, "/ownedObjects"):
			return `{"value":[{"@odata.type":"#microsoft.graph.group","id":"g0","displayName":"staff","isAssignableToRole":false}]}`
		case path.Base(p) == u2:
			return `{"id":"` + u2 + `","userPrincipalName":"u2@example.com","onPremisesSyncEnabled":true,"onPremisesSecurityIdentifier":"S-1-5-21-1-2-3-1105"}`
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
			return d.apiWrite(context.Background(), entraAPIIn{ActionParam: ActionParam{"patch"}, Path: "/v1.0/users/" + u1, Reason: "r", Body: map[string]any{"jobTitle": "x"}})
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
