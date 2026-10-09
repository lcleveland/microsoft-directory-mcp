package graph

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// probeStub answers the token endpoint with token and every Graph path in
// routes with its status and body; anything else is 404.
func probeStub(t *testing.T, token string, routes map[string]reply) *Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"`+token+`","expires_in":3599}`)
			return
		}
		rp, ok := routes[r.URL.Path]
		if !ok {
			rp = reply{404, `{"error":{"code":"Request_ResourceNotFound"}}`}
		}
		w.WriteHeader(rp.status)
		io.WriteString(w, rp.body)
	}))
	t.Cleanup(ts.Close)
	c := newClient(t, ts.URL, ts.URL)
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

type reply struct {
	status int
	body   string
}

func jwt(payload string) string {
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

var ok200 = reply{200, `{"value":[]}`}

// A SKU with Exchange only: no P1, no P2.
var noPremium = reply{200, `{"value":[{"skuPartNumber":"EXCHANGESTANDARD","capabilityStatus":"Enabled",
	"servicePlans":[{"servicePlanId":"9aaf7827-d63c-4b61-89c3-182f06f82e5c","servicePlanName":"EXCHANGE_S_STANDARD","provisioningStatus":"Success"}]}]}`}

func TestProbeRolesAndLicences(t *testing.T) {
	c := probeStub(t, jwt(`{"roles":["User.Read.All","AuditLog.Read.All"]}`), map[string]reply{
		"/v1.0/subscribedSkus":                  noPremium,
		"/v1.0/deviceManagement/managedDevices": ok200,
	})
	p := c.Probe(context.Background())
	if !slices.Equal(p.Roles, []string{"User.Read.All", "AuditLog.Read.All"}) {
		t.Errorf("roles %v", p.Roles)
	}
	for lic, want := range map[string]string{"P1": Absent, "P2": Absent, "Intune": Present} {
		if p.Licences[lic] != want {
			t.Errorf("%s = %q, want %q", lic, p.Licences[lic], want)
		}
	}
	if p.Groups != nil {
		t.Errorf("group reads ran with roles known: %v", p.Groups)
	}
}

func TestProbeP1FromSkus(t *testing.T) {
	c := probeStub(t, jwt(`{"roles":[]}`), map[string]reply{
		"/v1.0/subscribedSkus": {200, `{"value":[{"capabilityStatus":"Warning","servicePlans":[
			{"servicePlanId":"41781fb2-bc02-4b7c-bd55-b576c07bb09d","provisioningStatus":"Success"},
			{"servicePlanId":"eec0eb4f-6444-4f95-aba0-50c24d67f998","provisioningStatus":"Disabled"}]}]}`},
	})
	p := c.Probe(context.Background())
	if p.Licences["P1"] != Present || p.Licences["P2"] != Absent {
		t.Errorf("licences %v", p.Licences)
	}
}

// All three licence error shapes on the Intune read mean "no licence".
func TestProbeLicenceShapes(t *testing.T) {
	for _, rp := range []reply{
		{403, `{"error":{"code":"Forbidden","message":"x"}}`},
		{403, `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"x"}}`},
		{400, `{"error":{"code":"AadPremiumLicenseRequired","message":"x"}}`},
	} {
		c := probeStub(t, jwt(`{"roles":[]}`), map[string]reply{
			"/v1.0/subscribedSkus":                  noPremium,
			"/v1.0/deviceManagement/managedDevices": rp,
		})
		if got := c.Probe(context.Background()).Licences["Intune"]; got != Absent {
			t.Errorf("%s: Intune %q", rp.body, got)
		}
	}
}

// An opaque token (no roles claim) and no subscribedSkus fall back to one
// $top=1 read per group and to licence read probes.
func TestProbeFallback(t *testing.T) {
	c := probeStub(t, "opaque", map[string]reply{
		"/v1.0/users":                               ok200,
		"/v1.0/auditLogs/directoryAudits":           {403, `{"error":{"code":"Authorization_RequestDenied"}}`},
		"/v1.0/identity/conditionalAccess/policies": {503, `{"error":{"code":"ServiceUnavailable"}}`},
		"/v1.0/subscribedSkus":                      {403, `{"error":{"code":"Authorization_RequestDenied"}}`},
		"/v1.0/auditLogs/signIns":                   {403, `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant"}}`},
		"/v1.0/identityProtection/riskyUsers":       ok200,
		"/v1.0/deviceManagement/managedDevices":     ok200,
	})
	p := c.Probe(context.Background())
	if p.Roles != nil {
		t.Errorf("roles %v", p.Roles)
	}
	for g, want := range map[string]string{"identity": ReadOK, "security": ReadPermission, "policy": ReadUnknown, "devices": ReadOK} {
		if got := p.Groups[g].State; got != want {
			t.Errorf("group %s = %q, want %q", g, got, want)
		}
	}
	for lic, want := range map[string]string{"P1": Absent, "P2": Present, "Intune": Present} {
		if p.Licences[lic] != want {
			t.Errorf("%s = %q, want %q", lic, p.Licences[lic], want)
		}
	}
	if len(p.Notes) == 0 {
		t.Error("no note says why the fallback ran")
	}
}
