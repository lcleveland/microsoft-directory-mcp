package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ProbeDeadline bounds the whole startup probe.
const ProbeDeadline = 10 * time.Second

// Licence states.
const (
	Present = "present"
	Absent  = "absent"
	Unknown = "unknown"
)

// Read probe states.
const (
	ReadOK         = "ok"
	ReadLicence    = "licence"
	ReadPermission = "permission"
	ReadUnknown    = "unknown" // throttled, 5xx, timeout: fail open
)

// Read is the outcome of one $top=1 read probe.
type Read struct {
	State  string `json:"state"`
	Status int    `json:"status,omitempty"`
	Code   string `json:"code,omitempty"`
}

// Probe is what the startup probe learned. A nil *Probe (--no-probe) shows
// everything; so does anything Unknown.
type Probe struct {
	Roles    []string          `json:"roles"`                 // the token's roles claim; nil when unreadable
	Licences map[string]string `json:"licences"`              // P1, P2, Intune
	Groups   map[string]Read   `json:"group_reads,omitempty"` // fallback reads by tool group, only when Roles is nil
	Notes    []string          `json:"notes,omitempty"`
}

// Service plan ids, matched in any SKU (P1 and P2 ride inside many bundles).
// See docs/research/entra-permissions-and-licensing.md.
var planIDs = map[string]string{
	"P1": "41781fb2-bc02-4b7c-bd55-b576c07bb09d",
	"P2": "eec0eb4f-6444-4f95-aba0-50c24d67f998",
}

// licenceReads decide a licence by a read it gates: Intune always (the SKU
// check under-reports it), P1 and P2 only when subscribedSkus fails.
var licenceReads = map[string]string{
	"P1":     "/v1.0/auditLogs/signIns",
	"P2":     "/v1.0/identityProtection/riskyUsers",
	"Intune": "/v1.0/deviceManagement/managedDevices",
}

// groupReads stand in for the roles claim when it can't be read: one read
// per tool group (core has no gated reads).
var groupReads = map[string]string{
	"identity": "/v1.0/users",
	"security": "/v1.0/auditLogs/directoryAudits",
	"policy":   "/v1.0/identity/conditionalAccess/policies",
	"devices":  "/v1.0/devices",
	"infra":    "/v1.0/organization",
}

// Probe runs the startup probe under ProbeDeadline.
// ponytail: sequential, about eight GETs; run them concurrently if startup drags.
func (c *Client) Probe(ctx context.Context) *Probe {
	ctx, cancel := context.WithTimeout(ctx, ProbeDeadline)
	defer cancel()
	p := &Probe{Licences: map[string]string{"P1": Unknown, "P2": Unknown, "Intune": Unknown}}

	roles, err := c.roles(ctx)
	if err != nil {
		p.Notes = append(p.Notes, "roles claim unreadable ("+err.Error()+"); fell back to one read per tool group")
		p.Groups = map[string]Read{}
		for g, path := range groupReads {
			p.Groups[g] = c.read(ctx, path)
		}
	} else {
		p.Roles = roles
	}

	var skus struct {
		Value []struct {
			CapabilityStatus string `json:"capabilityStatus"`
			ServicePlans     []struct {
				ServicePlanID      string `json:"servicePlanId"`
				ProvisioningStatus string `json:"provisioningStatus"`
			} `json:"servicePlans"`
		} `json:"value"`
	}
	if err := c.Get(ctx, "/v1.0/subscribedSkus?$select=capabilityStatus,servicePlans", &skus); err != nil {
		p.Notes = append(p.Notes, "subscribedSkus failed ("+err.Error()+"); P1 and P2 decided by read probes")
		for _, lic := range []string{"P1", "P2"} {
			p.Licences[lic] = licence(c.read(ctx, licenceReads[lic]))
		}
	} else {
		for lic, id := range planIDs {
			p.Licences[lic] = Absent
			for _, s := range skus.Value {
				if s.CapabilityStatus != "Enabled" && s.CapabilityStatus != "Warning" {
					continue
				}
				for _, sp := range s.ServicePlans {
					if sp.ServicePlanID == id && sp.ProvisioningStatus == "Success" {
						p.Licences[lic] = Present
					}
				}
			}
		}
	}
	p.Licences["Intune"] = licence(c.read(ctx, licenceReads["Intune"]))
	return p
}

// read GETs path?$top=1 and classifies the reply. 2xx and 404 are ok. The
// licence shapes are 403 Forbidden, 403
// Authentication_RequestFromNonPremiumTenantOrB2CTenant and 400
// AadPremiumLicenseRequired; any other 403 is a missing permission.
func (c *Client) read(ctx context.Context, path string) Read {
	var discard json.RawMessage
	err := c.Get(ctx, path+"?$top=1", &discard)
	var ae *APIError
	switch {
	case err == nil:
		return Read{State: ReadOK}
	case !errors.As(err, &ae):
		return Read{State: ReadUnknown, Code: err.Error()}
	}
	r := Read{State: ReadUnknown, Status: ae.Status, Code: ae.Code}
	switch {
	case ae.Status == http.StatusNotFound:
		r.State = ReadOK
	case ae.Status == http.StatusForbidden && (ae.Code == "Forbidden" || ae.Code == "Authentication_RequestFromNonPremiumTenantOrB2CTenant"),
		ae.Status == http.StatusBadRequest && ae.Code == "AadPremiumLicenseRequired":
		r.State = ReadLicence
	case ae.Status == http.StatusForbidden:
		r.State = ReadPermission
	}
	return r
}

// licence maps a licence read probe to a licence state. A missing
// permission says nothing about the licence.
func licence(r Read) string {
	switch r.State {
	case ReadOK:
		return Present
	case ReadLicence:
		return Absent
	}
	return Unknown
}

// roles decodes the roles claim of the current token without verifying it:
// the server fetched the token itself. Microsoft calls Graph tokens opaque,
// hence the fallback when this fails.
func (c *Client) roles(ctx context.Context) ([]string, error) {
	tok, _, err := c.bearer(ctx, false)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	var claims struct {
		Roles *[]string `json:"roles"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	if claims.Roles == nil {
		return nil, errors.New("token has no roles claim")
	}
	return *claims.Roles, nil
}
