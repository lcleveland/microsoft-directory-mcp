package tools

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

type fakeIn struct {
	ActionParam
}

// fakeRoster stands in for the real one: two Entra tools in different
// groups and one AD tool.
func fakeRoster() []Tool {
	add := func(s *mcp.Server, d Deps, t Tool, visible []string) {
		addActionTool(s, d, t, &mcp.Tool{Name: t.Name, Description: "fake"}, visible,
			func(_ context.Context, _ *mcp.CallToolRequest, in fakeIn) (*mcp.CallToolResult, map[string]string, error) {
				return nil, map[string]string{"ran": in.Action}, nil
			})
	}
	return []Tool{
		{Name: "entra_fake", Group: "identity", add: add, Actions: []Action{
			{Name: "search", Perms: []string{"User.Read.All", "Directory.Read.All"}},
			{Name: "signins", Perms: []string{"AuditLog.Read.All"}, Licence: "P1"},
		}},
		{Name: "entra_pol", Group: "policy", add: add, Actions: []Action{
			{Name: "get", Perms: []string{"Policy.Read.All"}},
		}},
		{Name: "ad_fake", Group: "identity", add: add, Actions: []Action{
			{Name: "get"},
			{Name: "psos", ADProbe: "pso-read"},
		}},
	}
}

// session registers the fake roster over both sides (against a Graph stub
// that answers everything) and connects a client.
func session(t *testing.T, cfg *config.Config, d Deps) *mcp.ClientSession {
	t.Helper()
	saved := roster
	roster = fakeRoster()
	t.Cleanup(func() { roster = saved })

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"tok","expires_in":3599}`)
			return
		}
		io.WriteString(w, `{"value":[]}`)
	}))
	t.Cleanup(stub.Close)
	pemBytes, err := os.ReadFile("../graph/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if d.Graph, err = graph.New("tenant", "client", pemBytes, stub.URL, stub.URL, nil); err != nil {
		t.Fatal(err)
	}
	// Nothing listens there: ad_status fails fast but still reports visibility.
	cfg.AD = &config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}
	if d.AD, err = ad.New(cfg.AD, time.Second); err != nil {
		t.Fatal(err)
	}
	if cfg.ToolGroups == nil {
		cfg.ToolGroups = map[string]bool{}
		for _, g := range config.Groups {
			cfg.ToolGroups[g] = true
		}
	}

	cfg.Entra = &config.Entra{Cloud: "global", PasswordWriteback: "unknown"}
	d.Config = cfg

	s := mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	Register(s, d)
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
	return cs
}

// listed maps each listed tool to its action enum.
func listed(t *testing.T, cs *mcp.ClientSession) map[string][]string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, tl := range res.Tools {
		out[tl.Name] = nil
		schema, _ := tl.InputSchema.(map[string]any)
		props, _ := schema["properties"].(map[string]any)
		action, _ := props["action"].(map[string]any)
		enum, _ := action["enum"].([]any)
		for _, e := range enum {
			out[tl.Name] = append(out[tl.Name], e.(string))
		}
	}
	return out
}

func status(t *testing.T, cs *mcp.ClientSession, name string) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return res.StructuredContent.(map[string]any)
}

// hidden flattens a status's hidden_actions to "tool action: reason".
func hidden(sc map[string]any) []string {
	var out []string
	hs, _ := sc["hidden_actions"].([]any)
	for _, h := range hs {
		m := h.(map[string]any)
		out = append(out, m["tool"].(string)+" "+m["action"].(string)+": "+m["reason"].(string))
	}
	return out
}

func TestNoProbeShowsEverything(t *testing.T) {
	cs := session(t, &config.Config{NoProbe: true}, Deps{})
	got := listed(t, cs)
	for tool, want := range map[string][]string{
		"entra_fake": {"search", "signins"}, "entra_pol": {"get"}, "ad_fake": {"get", "psos"},
	} {
		if !slices.Equal(got[tool], want) {
			t.Errorf("%s actions %v, want %v", tool, got[tool], want)
		}
	}
	if sc := status(t, cs, "entra_status"); len(hidden(sc)) != 0 || sc["probe_skipped"] != true {
		t.Errorf("entra_status %v", sc)
	}
}

// With the Entra side on, the OData filter guide is served.
func TestEntraGuideServed(t *testing.T) {
	cs := session(t, &config.Config{NoProbe: true}, Deps{})
	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "entra://guide/odata-filter"})
	if err != nil || len(res.Contents) != 1 || !strings.Contains(res.Contents[0].Text, "ConsistencyLevel") {
		t.Errorf("guide: %v %v", res, err)
	}
}

func TestGroupFilterHidesTools(t *testing.T) {
	cs := session(t, &config.Config{ToolGroups: map[string]bool{"core": true, "identity": true}}, Deps{})
	got := listed(t, cs)
	if _, ok := got["entra_pol"]; ok {
		t.Errorf("policy tool listed with policy off: %v", got)
	}
	for _, name := range []string{"entra_fake", "ad_fake", "ad_status", "entra_status"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s missing: %v", name, got)
		}
	}
	if g := status(t, cs, "ad_status")["enabled_groups"]; !slices.Equal(anyStrings(g), []string{"core", "identity"}) {
		t.Errorf("enabled_groups %v", g)
	}
}

func TestRolesAndLicencesHideActions(t *testing.T) {
	cs := session(t, &config.Config{}, Deps{EntraProbe: &graph.Probe{
		Roles:    []string{"Directory.Read.All", "AuditLog.Read.All"},
		Licences: map[string]string{"P1": graph.Absent, "P2": graph.Absent, "Intune": graph.Unknown},
	}})
	got := listed(t, cs)
	if !slices.Equal(got["entra_fake"], []string{"search"}) {
		t.Errorf("entra_fake actions %v", got["entra_fake"])
	}
	if _, ok := got["entra_pol"]; ok {
		t.Error("entra_pol listed with no visible actions")
	}
	h := hidden(status(t, cs, "entra_status"))
	want := []string{
		"entra_fake signins: licence: needs P1",
		"entra_pol get: missing permission: needs one of Policy.Read.All",
	}
	if !slices.Equal(h, want) {
		t.Errorf("hidden %q, want %q", h, want)
	}
	// A hidden action is refused even if called anyway.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "entra_fake", Arguments: map[string]any{"action": "signins"}})
	if err == nil && !res.IsError {
		t.Errorf("hidden action ran: %+v", res.StructuredContent)
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "entra_fake", Arguments: map[string]any{"action": "search"}})
	if err != nil || res.IsError {
		t.Errorf("visible action: %v %+v", err, res)
	}
}

func TestFallbackReadHidesGroup(t *testing.T) {
	cs := session(t, &config.Config{}, Deps{EntraProbe: &graph.Probe{
		Licences: map[string]string{"P1": graph.Unknown},
		Groups: map[string]graph.Read{
			"identity": {State: graph.ReadOK},
			"policy":   {State: graph.ReadPermission, Status: 403, Code: "Authorization_RequestDenied"},
		},
	}})
	got := listed(t, cs)
	if !slices.Equal(got["entra_fake"], []string{"search", "signins"}) {
		t.Errorf("entra_fake actions %v", got["entra_fake"])
	}
	if _, ok := got["entra_pol"]; ok {
		t.Error("entra_pol listed though its group read was refused")
	}
	h := hidden(status(t, cs, "entra_status"))
	if len(h) != 1 || !strings.HasPrefix(h[0], "entra_pol get: policy read probe refused: permission") {
		t.Errorf("hidden %q", h)
	}
}

func TestADReadProbeHidesAction(t *testing.T) {
	cs := session(t, &config.Config{}, Deps{ADProbe: &ad.Probe{Bound: true, Reads: map[string]string{"pso-read": "insufficient access"}}})
	if got := listed(t, cs)["ad_fake"]; !slices.Equal(got, []string{"get"}) {
		t.Errorf("ad_fake actions %v", got)
	}
	if h := hidden(status(t, cs, "ad_status")); !slices.Equal(h, []string{"ad_fake psos: AD right: pso-read: insufficient access"}) {
		t.Errorf("hidden %q", h)
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
