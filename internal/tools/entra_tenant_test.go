package tools

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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

// Service health ids aren't GUIDs: a message id reads in full, and an id
// that would leave the collection is refused before any call.
func TestHealthMessageByID(t *testing.T) {
	cs, seen := entraSession(t, nil, func(r *http.Request) string {
		return `{"id":"MC123456","title":"Change","body":{"content":"x"}}`
	})
	out, isErr := call(t, cs, "entra_health", map[string]any{"action": "messages", "id": "MC123456"})
	if isErr || out["body"] == nil {
		t.Errorf("get %v", out)
	}
	if _, isErr := call(t, cs, "entra_health", map[string]any{"action": "messages", "id": "../issues"}); !isErr {
		t.Error("path id accepted")
	}
	rs := seen()
	if len(rs) != 1 || rs[0].URL.Path != "/v1.0/admin/serviceAnnouncement/messages/MC123456" || rs[0].URL.Query().Has("$select") {
		t.Errorf("requests %v", rs)
	}
}
