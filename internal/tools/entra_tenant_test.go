package tools

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// expiring_credentials keeps the credentials that end inside the window,
// from apps and SPs alike, and never their secret material.
func TestExpiringCredentialsWindow(t *testing.T) {
	day := func(n int) string { return time.Now().UTC().AddDate(0, 0, n).Format(time.RFC3339) }
	cs, _ := entraSession(t, nil, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/applications") {
			return fmt.Sprintf(`{"value":[{"id":"a1","appId":"x1","displayName":"App","passwordCredentials":[`+
				`{"keyId":"k-past","endDateTime":%q,"hint":"abc"},{"keyId":"k-soon","displayName":"s","endDateTime":%q,"hint":"abc"},`+
				`{"keyId":"k-late","endDateTime":%q}],"keyCredentials":[]}]}`, day(-1), day(10), day(40))
		}
		return fmt.Sprintf(`{"value":[{"id":"s1","appId":"x2","displayName":"SP","passwordCredentials":[],`+
			`"keyCredentials":[{"keyId":"k-cert","endDateTime":%q,"key":"MIIC"}]}]}`, day(29))
	})
	out, isErr := call(t, cs, "entra_app", map[string]any{"action": "expiring_credentials", "days": 30})
	if isErr {
		t.Fatal(out)
	}
	var got []string
	for _, r := range out["results"].([]any) {
		m := r.(map[string]any)
		if m["hint"] != nil || m["key"] != nil {
			t.Errorf("secret material: %v", m)
		}
		got = append(got, fmt.Sprint(m["kind"], " ", m["credential"], " ", m["keyId"]))
	}
	if fmt.Sprint(got) != "[app password k-soon sp key k-cert]" {
		t.Errorf("results %v", got)
	}
	if _, isErr := call(t, cs, "entra_app", map[string]any{"action": "expiring_credentials", "days": -1}); !isErr {
		t.Error("negative window accepted")
	}
}

// The writeback hint is the newest audit event, whatever order Graph sends
// them in; without AuditLog.Read.All it is unknown and the log is not read.
func TestWritebackHint(t *testing.T) {
	reply := func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/directoryAudits") {
			return `{"value":[{"activityDisplayName":"Disable password writeback for directory","activityDateTime":"2026-01-02T00:00:00Z"},` +
				`{"activityDisplayName":"Enable password writeback for directory","activityDateTime":"2026-01-03T00:00:00Z"},` +
				`{"activityDisplayName":"Disable password writeback for directory","activityDateTime":"2026-01-01T00:00:00Z"}]}`
		}
		return `{"value":[{"id":"t","displayName":"Example"}]}`
	}
	for _, tc := range []struct {
		roles []string
		want  string
		reads int
	}{
		{[]string{"Organization.Read.All", "AuditLog.Read.All"}, "enabled 2026-01-03T00:00:00Z", 2},
		{[]string{"Organization.Read.All"}, "unknown <nil>", 1},
	} {
		cs, seen := entraSession(t, &graph.Probe{Roles: tc.roles}, reply)
		out, isErr := call(t, cs, "entra_org", map[string]any{"action": "info"})
		wb, _ := out["password_writeback"].(map[string]any)
		hint, _ := wb["audit_hint"].(map[string]any)
		if got := fmt.Sprint(hint["value"], " ", hint["activityDateTime"]); isErr || got != tc.want || wb["source"] != "operator-declared" {
			t.Errorf("roles %v: %v", tc.roles, out)
		}
		if n := len(seen()); n != tc.reads {
			t.Errorf("roles %v: %d Graph calls, want %d", tc.roles, n, tc.reads)
		}
	}
}

// Assignments name their role definition and principal.
func TestRoleAssignmentsNamed(t *testing.T) {
	cs, _ := entraSession(t, nil, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/roleDefinitions") {
			return `{"value":[{"id":"rd1","displayName":"User Administrator"}]}`
		}
		return `{"value":[{"id":"a1","roleDefinitionId":"rd1","principalId":"p1","directoryScopeId":"/",` +
			`"principal":{"@odata.type":"#microsoft.graph.user","id":"p1","displayName":"Ada","mail":"a@example.com"}}]}`
	})
	out, isErr := call(t, cs, "entra_role", map[string]any{"action": "assignments"})
	rs, _ := out["results"].([]any)
	if isErr || len(rs) != 1 || fmt.Sprint(rs[0]) != "map[directoryScopeId:/ id:a1 principal:map[@odata.type:#microsoft.graph.user displayName:Ada id:p1] "+
		"roleDefinition:map[displayName:User Administrator id:rd1]]" {
		t.Errorf("%v", out)
	}
}
