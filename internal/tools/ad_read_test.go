package tools

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
)

// adSession registers the real AD roster under probe and connects a client.
func adSession(t *testing.T, probe *ad.Probe) *mcp.ClientSession {
	t.Helper()
	cfg := &config.Config{ToolGroups: map[string]bool{}, AD: &config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}}
	for _, g := range config.Groups {
		cfg.ToolGroups[g] = true
	}
	a, err := ad.New(cfg.AD, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	Register(s, Deps{Config: cfg, AD: a, ADProbe: probe})
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

// The real AD roster registers (its input schemas build) with every action,
// and the filter guide is served.
func TestADReadRosterRegisters(t *testing.T) {
	cs := adSession(t, nil)
	ctx := context.Background()
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"ad_user": {"search", "get", "resultant_policy"}, "ad_group": {"search", "get", "members"}, "ad_computer": {"search", "get"},
		"ad_ou": {"search", "get", "tree"}, "ad_object": {"get", "search_deleted"}, "ad_gpo": {"search", "get", "links"},
		"ad_policy": {"domain_default", "psos"}, "ad_api": {"search"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: actions %v, want %v", name, got[name], want)
		}
	}
	res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "ad://guide/ldap-filter"})
	if err != nil || len(res.Contents) != 1 || len(res.Contents[0].Text) < 100 {
		t.Errorf("guide: %v %v", res, err)
	}
}

// Without the right to read PSOs, the actions that need it are hidden.
func TestPSOProbeHidesActions(t *testing.T) {
	cs := adSession(t, &ad.Probe{Bound: true, Reads: map[string]string{"pso-read": "cannot read the Password Settings Container"}})
	got := listed(t, cs)
	if !slices.Equal(got["ad_policy"], []string{"domain_default"}) || !slices.Equal(got["ad_user"], []string{"search", "get"}) {
		t.Errorf("ad_policy %v, ad_user %v", got["ad_policy"], got["ad_user"])
	}
	want := []string{"ad_user resultant_policy: AD right: pso-read: cannot read the Password Settings Container",
		"ad_policy psos: AD right: pso-read: cannot read the Password Settings Container"}
	if h := hidden(status(t, cs, "ad_status")); !slices.Equal(h, want) {
		t.Errorf("hidden %q", h)
	}
}

func TestAncestors(t *testing.T) {
	got, err := ancestors("DC=corp,DC=example,DC=com", `OU=b,OU=Smith\, J,DC=corp,DC=example,DC=com`)
	want := []string{"DC=corp,DC=example,DC=com", `OU=Smith\, J,DC=corp,DC=example,DC=com`, `OU=b,OU=Smith\, J,DC=corp,DC=example,DC=com`}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("%q %v", got, err)
	}
	if _, err := ancestors("DC=child,DC=corp", "OU=a,DC=corp"); err == nil {
		t.Error("not under: want an error")
	}
}

func TestJoinFilter(t *testing.T) {
	for _, tc := range []struct {
		parts []string
		want  string
	}{
		{[]string{"(objectClass=user)", "", "(anr=jo)"}, "(&(objectClass=user)(anr=jo))"},
		{[]string{"(objectClass=user)", "department=IT"}, "(&(objectClass=user)(department=IT))"},
	} {
		if got, err := joinFilter(tc.parts...); err != nil || got != tc.want {
			t.Errorf("%v: %q %v", tc.parts, got, err)
		}
	}
	if _, err := joinFilter("(objectClass=user)", "(broken"); err == nil {
		t.Error("broken filter: want an error")
	}
}

func TestOffsetCursor(t *testing.T) {
	c := encodeOffset(400, "CN=g [mail]")
	if off, err := decodeOffset(c, "CN=g [mail]"); err != nil || off != 400 {
		t.Errorf("round trip: %d %v", off, err)
	}
	for _, bad := range []string{"garbage!", encodeOffset(400, "CN=other []")} {
		if _, err := decodeOffset(bad, "CN=g [mail]"); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if encodeOffset(-1, "x") != "" {
		t.Error("end of members: want no cursor")
	}
}
