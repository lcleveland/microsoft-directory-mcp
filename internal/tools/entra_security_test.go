package tools

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// errText is the text of a call that must fail.
func errText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Errorf("%s %v: no error", name, args)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Without P1 and P2 the probe hides sign-ins and risk, and entra_status
// says why; audit stays (it works on Free).
func TestSignInAndRiskGatedByLicence(t *testing.T) {
	cs, _ := entraSession(t, &graph.Probe{Licences: map[string]string{"P1": graph.Absent, "P2": graph.Absent}},
		func(*http.Request) string { return `{"value":[]}` })
	got := listed(t, cs)
	for _, name := range []string{"entra_signin", "entra_risk"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s registered without its licence", name)
		}
	}
	if !slices.Equal(got["entra_audit"], []string{"search"}) {
		t.Errorf("entra_audit actions %v", got["entra_audit"])
	}
	status, _ := call(t, cs, "entra_status", map[string]any{})
	var hidden []string
	for _, h := range status["hidden_actions"].([]any) {
		m := h.(map[string]any)
		hidden = append(hidden, fmt.Sprint(m["tool"], " ", m["action"], ": ", m["reason"]))
	}
	want := []string{"entra_signin search: licence: needs P1", "entra_risk risky_users: licence: needs P2", "entra_risk risk_detections: licence: needs P2"}
	for _, w := range want {
		if !slices.Contains(hidden, w) {
			t.Errorf("hidden %v lacks %q", hidden, w)
		}
	}
}

// When the probe could not decide, Graph's licence refusals come back as
// licence errors at call time.
func TestLicenceRefusalAtCallTime(t *testing.T) {
	cs, _ := entraSession(t, nil, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/signIns") {
			return "403 Authentication_RequestFromNonPremiumTenantOrB2CTenant"
		}
		return "403 Forbidden"
	})
	for tool, want := range map[string]string{"entra_signin search": "needs Entra ID P1", "entra_risk risky_users": "needs Entra ID P2"} {
		name, action, _ := strings.Cut(tool, " ")
		if got := errText(t, cs, name, map[string]any{"action": action}); !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", tool, got, want)
		}
	}
}

// Log lists ask Graph for a page of 200 without $select (the logs don't
// take it) and cut each row to the brief here.
func TestLogBriefs(t *testing.T) {
	cs, seen := entraSession(t, nil, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/signIns") {
			return `{"value":[{"id":"s1","createdDateTime":"2026-01-01T00:00:00Z","userPrincipalName":"ada@example.com","appDisplayName":"App",` +
				`"ipAddress":"192.0.2.1","status":{"errorCode":0,"failureReason":"x"},"conditionalAccessStatus":"success",` +
				`"location":{"city":"Springfield","countryOrRegion":"US","geoCoordinates":{}},"deviceDetail":{}}]}`
		}
		return `{"value":[{"id":"a1","activityDateTime":"2026-01-01T00:00:00Z","activityDisplayName":"Add user","category":"UserManagement",` +
			`"result":"success","initiatedBy":{"app":null},"targetResources":[{"id":"t1","displayName":"Ada","modifiedProperties":[]}],"additionalDetails":[]}]}`
	})
	audit, _ := call(t, cs, "entra_audit", map[string]any{"action": "search"})
	if got := fmt.Sprint(audit["results"]); got != "[map[activityDateTime:2026-01-01T00:00:00Z activityDisplayName:Add user category:UserManagement "+
		"initiatedBy:map[app:<nil>] result:success targetResources:[map[displayName:Ada]]]]" {
		t.Errorf("audit %s", got)
	}
	signin, _ := call(t, cs, "entra_signin", map[string]any{"action": "search"})
	if got := fmt.Sprint(signin["results"]); got != "[map[appDisplayName:App conditionalAccessStatus:success createdDateTime:2026-01-01T00:00:00Z "+
		"ipAddress:192.0.2.1 location:map[city:Springfield countryOrRegion:US] status:map[errorCode:0] userPrincipalName:ada@example.com]]" {
		t.Errorf("sign-in %s", got)
	}
	fields, _ := call(t, cs, "entra_audit", map[string]any{"action": "search", "fields": []string{"id", "additionalDetails"}})
	if got := fmt.Sprint(fields["results"]); got != "[map[additionalDetails:[] id:a1]]" {
		t.Errorf("audit fields %s", got)
	}
	for _, r := range seen() {
		if q := r.URL.Query(); q.Get("$top") != "200" || q.Has("$select") {
			t.Errorf("%s: query %v", r.URL.Path, q)
		}
	}
}

// The CA list selects the brief; the get returns the whole policy.
func TestConditionalAccessListBriefGetFull(t *testing.T) {
	const id = "00000000-0000-0000-0000-0000000000ca"
	cs, seen := entraSession(t, nil, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/policies") {
			return `{"value":[{"id":"` + id + `","displayName":"Require MFA","state":"enabled","modifiedDateTime":null}]}`
		}
		return `{"id":"` + id + `","displayName":"Require MFA","conditions":{"users":{"includeUsers":["All"]}},` +
			`"grantControls":{"builtInControls":["mfa"]},"sessionControls":null}`
	})
	list, isErr := call(t, cs, "entra_policy", map[string]any{"action": "conditional_access"})
	if isErr || len(list["results"].([]any)) != 1 {
		t.Errorf("list %v", list)
	}
	got, isErr := call(t, cs, "entra_policy", map[string]any{"action": "conditional_access", "id": id})
	if _, ok := got["sessionControls"]; isErr || got["conditions"] == nil || got["grantControls"] == nil || !ok {
		t.Errorf("get %v", got)
	}
	rs := seen()
	if sel := rs[0].URL.Query().Get("$select"); sel != "id,displayName,state,modifiedDateTime" {
		t.Errorf("list $select %q", sel)
	}
	if rs[1].URL.Path != "/v1.0/identity/conditionalAccess/policies/"+id || rs[1].URL.Query().Has("$select") {
		t.Errorf("get %s", rs[1].URL)
	}
}
