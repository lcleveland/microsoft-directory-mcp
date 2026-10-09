package tools

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
)

const testSID = "S-1-5-21-1-2-3-1104"

// bothSides is Deps with a Graph stub and an AD client whose SID lookup
// is find.
func bothSides(t *testing.T, find func(sid, class string) (*ldap.Entry, error), reply func(r *http.Request) string) (Deps, func() []*http.Request) {
	t.Helper()
	g, seen := graphStub(t, reply)
	a, err := ad.New(&config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	old := adBySID
	adBySID = func(_ context.Context, _ Deps, sid, class string) (*ldap.Entry, error) { return find(sid, class) }
	t.Cleanup(func() { adBySID = old })
	return Deps{Config: &config.Config{}, AD: a, Graph: g}, seen
}

// AD to Entra: the SID filters the Entra collection; Entra to AD: the
// SID resolves the AD object.
func TestCounterpartJoinsBySID(t *testing.T) {
	d, seen := bothSides(t, func(sid, class string) (*ldap.Entry, error) {
		if sid != testSID || class != adUsers.class {
			t.Errorf("AD lookup %s %s", sid, class)
		}
		return ldap.NewEntry("CN=ada,DC=corp,DC=example,DC=com", nil), nil
	}, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/onPremisesSyncBehavior") {
			return "403"
		}
		return `{"value":[{"id":"u1","onPremisesSyncEnabled":true}]}`
	})
	ctx := context.Background()
	c, err := d.fromAD(ctx, joinUser, testSID, "")
	if err != nil || *c != (Counterpart{ID: "u1", SourceOfAuthority: "forest", Source: "onPremisesSyncEnabled"}) {
		t.Errorf("from AD: %+v %v", c, err)
	}
	if f := seen()[0].URL.Query().Get("$filter"); seen()[0].URL.Path != "/v1.0/users" || f != "onPremisesSecurityIdentifier eq '"+testSID+"'" {
		t.Errorf("lookup %s", seen()[0].URL)
	}
	c, err = d.fromEntra(ctx, joinUser, map[string]any{"id": "u1", "onPremisesSecurityIdentifier": testSID, "onPremisesSyncEnabled": true})
	if err != nil || *c != (Counterpart{ID: "CN=ada,DC=corp,DC=example,DC=com", SourceOfAuthority: "forest", Source: "onPremisesSyncEnabled"}) {
		t.Errorf("from Entra: %+v %v", c, err)
	}
}

// isCloudManaged decides when Graph answers it; on 403, 404 or 400 the answer
// falls back to onPremisesSyncEnabled, and says which it came from.
func TestSourceOfAuthority(t *testing.T) {
	for _, tc := range []struct {
		behavior string
		sync     any
		want     Counterpart
	}{
		{`{"isCloudManaged":true}`, true, Counterpart{ID: "u1", SourceOfAuthority: "tenant", Source: "onPremisesSyncBehavior.isCloudManaged"}},
		{`{"isCloudManaged":false}`, true, Counterpart{ID: "u1", SourceOfAuthority: "forest", Source: "onPremisesSyncBehavior.isCloudManaged"}},
		{"403", true, Counterpart{ID: "u1", SourceOfAuthority: "forest", Source: "onPremisesSyncEnabled"}},
		{"404", nil, Counterpart{ID: "u1", SourceOfAuthority: "tenant", Source: "onPremisesSyncEnabled"}},
		{"400 Request_BadRequest", true, Counterpart{ID: "u1", SourceOfAuthority: "forest", Source: "onPremisesSyncEnabled"}},
		{"403", false, Counterpart{ID: "u1", SourceOfAuthority: "tenant", Source: "onPremisesSyncEnabled"}},
	} {
		d, _ := bothSides(t, nil, func(r *http.Request) string {
			if strings.HasSuffix(r.URL.Path, "/onPremisesSyncBehavior") {
				return tc.behavior
			}
			b := `{"value":[{"id":"u1","onPremisesSyncEnabled":null}]}`
			if tc.sync != nil {
				b = strings.Replace(b, "null", map[bool]string{true: "true", false: "false"}[tc.sync.(bool)], 1)
			}
			return b
		})
		if c, err := d.fromAD(context.Background(), joinGroup, testSID, ""); err != nil || *c != tc.want {
			t.Errorf("%s %v: %+v %v", tc.behavior, tc.sync, c, err)
		}
	}
}

// Devices have no onPremisesSyncBehavior: they always fall back.
func TestDeviceAuthorityFallsBack(t *testing.T) {
	d, seen := bothSides(t, nil, func(*http.Request) string { return `{"value":[{"id":"dev1","onPremisesSyncEnabled":true}]}` })
	c, err := d.fromAD(context.Background(), joinDevice, testSID, "")
	if err != nil || *c != (Counterpart{ID: "dev1", SourceOfAuthority: "forest", Source: "onPremisesSyncEnabled"}) || len(seen()) != 1 {
		t.Errorf("%+v %v, %d calls", c, err, len(seen()))
	}
	if seen()[0].URL.Path != "/v1.0/devices" {
		t.Errorf("lookup %s", seen()[0].URL.Path)
	}
}

// msDS-ObjectSoa=Cloud on the AD object hands it to the tenant; an AD
// object with no Entra counterpart and an Entra object with no SID belong
// to their own side.
func TestUnlinkedAndCloudSoA(t *testing.T) {
	d, seen := bothSides(t, func(string, string) (*ldap.Entry, error) {
		return ldap.NewEntry("CN=ada,DC=corp", map[string][]string{"msDS-ObjectSoa": {"Cloud"}}), nil
	}, func(*http.Request) string { return `{"value":[]}` })
	ctx := context.Background()
	if c, _ := d.fromAD(ctx, joinUser, testSID, "Cloud"); c.SourceOfAuthority != "tenant" || c.Source != "msDS-ObjectSoa" {
		t.Errorf("AD Cloud: %+v", c)
	}
	if c, _ := d.fromAD(ctx, joinUser, testSID, ""); c.ID != "" || c.SourceOfAuthority != "forest" {
		t.Errorf("AD unlinked: %+v", c)
	}
	n := len(seen())
	if c, _ := d.fromEntra(ctx, joinUser, map[string]any{"id": "u1"}); c.ID != "" || c.SourceOfAuthority != "tenant" || len(seen()) != n {
		t.Errorf("cloud-only: %+v", c)
	}
	if c, _ := d.fromEntra(ctx, joinUser, map[string]any{"id": "u1", "onPremisesSecurityIdentifier": testSID}); c.ID != "CN=ada,DC=corp" || c.Source != "msDS-ObjectSoa" {
		t.Errorf("Entra, AD Cloud: %+v", c)
	}
}

// With only the Entra side configured, a get carries no counterpart.
func TestNoCounterpartWithOneSide(t *testing.T) {
	cs, seen := entraSession(t, nil, func(*http.Request) string {
		return `{"id":"u1","onPremisesSecurityIdentifier":"` + testSID + `","onPremisesSyncEnabled":true}`
	})
	out, isErr := call(t, cs, "entra_user", map[string]any{"action": "get", "id": "ada@example.com"})
	if _, ok := out["counterpart"]; isErr || ok || len(seen()) != 1 {
		t.Errorf("%v, %d calls", out, len(seen()))
	}
}

// With only the AD side configured, an AD get carries no counterpart and
// never tries the join.
func TestNoCounterpartADOnly(t *testing.T) {
	a, err := ad.New(&config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{"objectSid": testSID}
	Deps{Config: &config.Config{}, AD: a}.addCounterpart(out, func() (*Counterpart, error) {
		t.Error("joined with no Entra side")
		return nil, nil
	})
	if _, ok := out["counterpart"]; ok {
		t.Errorf("%v", out)
	}
}

// With both sides, an Entra get carries the block; a failed join is said
// in it rather than failing the get.
func TestEntraGetCarriesCounterpart(t *testing.T) {
	d, _ := bothSides(t, func(string, string) (*ldap.Entry, error) { return nil, ad.ErrNoMatch }, func(r *http.Request) string {
		if strings.HasSuffix(r.URL.Path, "/onPremisesSyncBehavior") {
			return "500"
		}
		return `{"id":"u1","onPremisesSecurityIdentifier":"` + testSID + `","onPremisesSyncEnabled":true}`
	})
	out, err := d.entraGetJoined(context.Background(), joinDevice, entraIn{ID: "00000000-0000-0000-0000-000000000001"})
	if c, _ := out["counterpart"].(*Counterpart); err != nil || c == nil || c.ID != "" || c.SourceOfAuthority != "forest" {
		t.Errorf("device: %v %v", out, err)
	}
	out, _ = d.groupGet(context.Background(), entraIn{ID: "00000000-0000-0000-0000-000000000001"})
	if e, _ := out["counterpart"].(map[string]string); !strings.Contains(e["error"], "500") {
		t.Errorf("group with a failing join: %v", out["counterpart"])
	}
}
