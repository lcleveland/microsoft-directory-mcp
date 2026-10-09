package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// entraSession registers the real Entra roster under probe against a Graph
// stub answering every call with reply, and returns the requests it saw.
func entraSession(t *testing.T, probe *graph.Probe, reply func(r *http.Request) string) (*mcp.ClientSession, func() []*http.Request) {
	t.Helper()
	var mu sync.Mutex
	var seen []*http.Request
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"tok","expires_in":3599}`)
			return
		}
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
		body := reply(r)
		if body == "403" {
			w.WriteHeader(http.StatusForbidden)
			body = `{"error":{"code":"Authorization_RequestDenied","message":"no"}}`
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(stub.Close)
	pemBytes, err := os.ReadFile("../graph/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.New("tenant", "client", pemBytes, stub.URL, stub.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ToolGroups: map[string]bool{}, Entra: &config.Entra{Cloud: "global"}}
	for _, grp := range config.Groups {
		cfg.ToolGroups[grp] = true
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	Register(s, Deps{Config: cfg, Graph: g, EntraProbe: probe})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, func() []*http.Request { mu.Lock(); defer mu.Unlock(); return slices.Clone(seen) }
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := res.StructuredContent.(map[string]any)
	return sc, res.IsError
}

func TestEntraReadRosterRegisters(t *testing.T) {
	cs, _ := entraSession(t, nil, func(*http.Request) string { return `{}` })
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"entra_user":   {"search", "get", "member_of", "devices", "licenses", "auth_methods", "registration"},
		"entra_group":  {"search", "get", "members", "owners"},
		"entra_device": {"search", "get", "owners", "managed_search", "managed_get"},
		"entra_api":    {"get"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: actions %v, want %v", name, got[name], want)
		}
	}
}

// Without an Intune licence the managed device actions are hidden.
func TestIntuneActionsHiddenWithoutIntune(t *testing.T) {
	cs, _ := entraSession(t, &graph.Probe{Licences: map[string]string{"P1": graph.Present, "Intune": graph.Absent}}, func(*http.Request) string { return `{}` })
	if got := listed(t, cs)["entra_device"]; !slices.Equal(got, []string{"search", "get", "owners"}) {
		t.Errorf("entra_device actions %v", got)
	}
}

// A user get selects the brief plus the curated set and expands the
// manager; without P1, signInActivity is left out and said so.
func TestUserGetSelectsFieldSets(t *testing.T) {
	for _, tc := range []struct {
		lic    string
		signIn bool
	}{{graph.Present, true}, {graph.Absent, false}} {
		cs, seen := entraSession(t, &graph.Probe{Licences: map[string]string{"P1": tc.lic}}, func(r *http.Request) string {
			if strings.HasSuffix(r.URL.Path, "/subscribedSkus") {
				return `{"value":[{"skuId":"sku-1","skuPartNumber":"EXAMPLE_SKU"}]}`
			}
			return `{"id":"u1","assignedLicenses":[{"skuId":"sku-1"}]}`
		})
		out, isErr := call(t, cs, "entra_user", map[string]any{"action": "get", "id": "ada@example.com"})
		if isErr {
			t.Fatalf("get: %v", out)
		}
		r := seen()[0]
		if r.URL.Path != "/v1.0/users/ada@example.com" || r.URL.Query().Get("$expand") != "manager($select=id,displayName)" {
			t.Errorf("request %s", r.URL)
		}
		sel := strings.Split(r.URL.Query().Get("$select"), ",")
		want := append(slices.Clone(entraUsers.brief), "onPremisesSamAccountName", "onPremisesLastSyncDateTime", "jobTitle",
			"department", "assignedLicenses", "lastPasswordChangeDateTime")
		if tc.signIn {
			want = append(want, "signInActivity")
		}
		slices.Sort(sel)
		slices.Sort(want)
		if !slices.Equal(sel, want) {
			t.Errorf("P1 %s: $select %v, want %v", tc.lic, sel, want)
		}
		if _, omitted := out["_omitted"]; omitted == tc.signIn {
			t.Errorf("P1 %s: _omitted %v", tc.lic, out["_omitted"])
		}
		lic, _ := out["assignedLicenses"].([]any)
		if len(lic) != 1 || lic[0].(map[string]any)["skuPartNumber"] != "EXAMPLE_SKU" {
			t.Errorf("licences not named: %v", out["assignedLicenses"])
		}
	}
}

func TestUserIDChecked(t *testing.T) {
	cs, seen := entraSession(t, nil, func(*http.Request) string { return `{}` })
	for _, id := range []string{"", "..", "ada", "00000000-0000-0000-0000-00000000000g"} {
		if out, isErr := call(t, cs, "entra_user", map[string]any{"action": "get", "id": id}); !isErr {
			t.Errorf("id %q accepted: %v", id, out)
		}
	}
	if _, isErr := call(t, cs, "entra_group", map[string]any{"action": "get", "id": "ada@example.com"}); !isErr {
		t.Error("group by UPN accepted")
	}
	if n := len(seen()); n != 0 {
		t.Errorf("%d calls to Graph", n)
	}
}

// Group members come back as briefs of their own kind.
func TestGroupMembersShapedByKind(t *testing.T) {
	cs, seen := entraSession(t, nil, func(*http.Request) string {
		return `{"value":[{"@odata.type":"#microsoft.graph.user","id":"u","userPrincipalName":"a@example.com","deviceId":null},` +
			`{"@odata.type":"#microsoft.graph.device","id":"d","deviceId":"x","userPrincipalName":null}]}`
	})
	out, isErr := call(t, cs, "entra_group", map[string]any{"action": "members", "id": "00000000-0000-0000-0000-000000000001", "transitive": true})
	if isErr {
		t.Fatal(out)
	}
	if p := seen()[0].URL.Path; p != "/v1.0/groups/00000000-0000-0000-0000-000000000001/transitiveMembers" {
		t.Errorf("path %s", p)
	}
	rs := out["results"].([]any)
	u, d := rs[0].(map[string]any), rs[1].(map[string]any)
	if _, ok := u["deviceId"]; ok || u["userPrincipalName"] != "a@example.com" {
		t.Errorf("user %v", u)
	}
	if _, ok := d["userPrincipalName"]; ok || d["deviceId"] != "x" || d["@odata.type"] != "#microsoft.graph.device" {
		t.Errorf("device %v", d)
	}
}

func TestAPIGetBetaUnstable(t *testing.T) {
	cs, seen := entraSession(t, nil, func(*http.Request) string { return `{"id":"x"}` })
	out, isErr := call(t, cs, "entra_api", map[string]any{"action": "get", "path": "/beta/organization/x"})
	if isErr || out["id"] != "x" || out["_unstable"] == nil {
		t.Errorf("beta: %v", out)
	}
	out, _ = call(t, cs, "entra_api", map[string]any{"action": "get", "path": "/v1.0/organization/x"})
	if out["_unstable"] != nil {
		t.Errorf("v1.0 marked unstable: %v", out)
	}
	for _, p := range []string{"/v2.0/x", "v1.0/x", "@evil.example.com/v1.0/x", "/beta"} {
		if _, isErr := call(t, cs, "entra_api", map[string]any{"action": "get", "path": p}); !isErr {
			t.Errorf("path %q accepted", p)
		}
	}
	if n := len(seen()); n != 2 {
		t.Errorf("%d calls to Graph, want 2", n)
	}
}

// With P1 undecided, a get Graph refuses for signInActivity is retried without it.
func TestUserGetDropsSignInOn403(t *testing.T) {
	cs, seen := entraSession(t, &graph.Probe{Licences: map[string]string{"P1": graph.Unknown}}, func(r *http.Request) string {
		if strings.Contains(r.URL.Query().Get("$select"), "signInActivity") {
			return "403"
		}
		return `{"id":"u1"}`
	})
	out, isErr := call(t, cs, "entra_user", map[string]any{"action": "get", "id": "00000000-0000-0000-0000-000000000001"})
	if isErr || out["id"] != "u1" || out["_omitted"] == nil || len(seen()) != 2 {
		t.Errorf("%v %d calls", out, len(seen()))
	}
}

// A device both owned and registered comes once with both relations.
func TestUserDevicesMerged(t *testing.T) {
	cs, _ := entraSession(t, nil, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/ownedDevices") {
			return `{"value":[{"id":"a"}]}`
		}
		return `{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"http://` + r.Host + `/next"}`
	})
	out, isErr := call(t, cs, "entra_user", map[string]any{"action": "devices", "id": "ada@example.com"})
	rs, _ := out["results"].([]any)
	if isErr || len(rs) != 2 || fmt.Sprint(rs[0].(map[string]any)["relation"]) != "[owned registered]" || out["_truncation"] == nil {
		t.Errorf("%v", out)
	}
	if _, isErr := call(t, cs, "entra_device", map[string]any{"action": "search", "query": "x"}); !isErr {
		t.Error("query on devices accepted")
	}
}

// Group get counts members and owners; a count Graph refuses is said so.
func TestGroupGetCounts(t *testing.T) {
	cs, _ := entraSession(t, nil, func(r *http.Request) string {
		switch {
		case strings.HasSuffix(r.URL.Path, "/members"):
			return `{"@odata.count":12,"value":[]}`
		case strings.HasSuffix(r.URL.Path, "/owners"):
			return "403"
		}
		return `{"id":"g"}`
	})
	out, isErr := call(t, cs, "entra_group", map[string]any{"action": "get", "id": "00000000-0000-0000-0000-000000000001"})
	if oc, _ := out["ownerCount"].(string); isErr || out["memberCount"] != float64(12) || !strings.HasPrefix(oc, "unavailable") {
		t.Errorf("%v", out)
	}
}
