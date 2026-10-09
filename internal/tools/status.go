// Package tools defines the MCP tools and registers the enabled ones.
package tools

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

type Deps struct {
	Config     *config.Config
	AD         *ad.Client    // nil when the AD side is off
	Graph      *graph.Client // nil when the Entra side is off
	ADProbe    *ad.Probe     // nil when not probed: everything shows
	EntraProbe *graph.Probe  // nil when not probed: everything shows
}

// Register adds the tools of each configured side and returns how many.
// A side that is off has no tools, and neither has a tool with no visible
// action.
func Register(s *mcp.Server, d Deps) int {
	n := 0
	if d.AD != nil {
		registerADStatus(s, d)
		n++
	}
	if d.Graph != nil {
		registerEntraStatus(s, d)
		n++
	}
	for _, t := range roster {
		if visible, _ := d.visibility(t); len(visible) > 0 {
			t.add(s, d, t, visible)
			n++
		}
	}
	return n
}

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(true)}

type ADStatus struct {
	Bound bool   `json:"bound"`
	DC    string `json:"dc"`
	TLS   string `json:"tls"` // ldaps or starttls
	// Only present when --ad-insecure-skip-verify is on.
	TLSWarning string      `json:"tls_warning,omitempty"`
	Forest     string      `json:"forest"`
	BindUser   string      `json:"bind_user"`
	RootDSE    *ad.RootDSE `json:"root_dse,omitempty"`
	// Each domain's serving DC and whether its PDC emulator answers.
	Domains []ad.DomainStatus `json:"domains,omitempty"`
	Detail  string            `json:"detail,omitempty"`
	// The startup probe, absent when --no-probe skipped it.
	Probe        *ad.Probe `json:"probe,omitempty"`
	ProbeSkipped bool      `json:"probe_skipped,omitempty"`
	Visibility
}

func registerADStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "ad_status",
		Title: "Active Directory connectivity check",
		Description: "Connect to a domain controller of the forest root domain over TLS, bind as the service account " +
			"and read the rootDSE. Reports the bind result, the TLS mode, the domain controller used and the naming " +
			"contexts; for every domain, the domain controller serving it and whether its PDC emulator (where writes " +
			"go) is reachable; then the " +
			"startup probe (domains, read probes), the enabled tool groups, the visible actions and each hidden " +
			"action with the reason it is hidden (a missing AD right).\n\n" +
			"Call this first when another ad_* tool fails: it tells an unreachable domain controller, a TLS " +
			"failure and a rejected bind apart.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ADStatus, error) {
		a := d.Config.AD
		out := ADStatus{TLS: a.TLS, Forest: a.Forest, BindUser: a.BindUser,
			Probe: d.ADProbe, ProbeSkipped: d.Config.NoProbe, Visibility: d.report("ad")}
		if a.InsecureSkipVerify {
			out.TLSWarning = "TLS verification disabled (--ad-insecure-skip-verify)"
		}
		conn, dc, root, err := d.AD.Root(ctx)
		out.DC, out.Bound, out.RootDSE = dc, conn != nil, root
		if err != nil {
			out.Detail = err.Error()
			return &mcp.CallToolResult{IsError: true}, out, nil
		}
		out.Domains, _ = d.AD.Status(ctx)
		return nil, out, nil
	})
}

type EntraStatus struct {
	Authenticated bool   `json:"authenticated"`
	TokenExpires  string `json:"token_expires,omitempty"`
	Cloud         string `json:"cloud"`
	Tenant        string `json:"tenant"`
	GraphURL      string `json:"graph_url"`
	// From GET /organization.
	OnPremisesSyncEnabled      *bool  `json:"on_premises_sync_enabled,omitempty"`
	OnPremisesLastSyncDateTime string `json:"on_premises_last_sync,omitempty"`
	Detail                     string `json:"detail,omitempty"`
	// From --entra-password-writeback: Graph cannot detect it.
	PasswordWriteback Declared `json:"password_writeback"`
	// The startup probe, absent when --no-probe skipped it.
	Probe        *graph.Probe `json:"probe,omitempty"`
	ProbeSkipped bool         `json:"probe_skipped,omitempty"`
	Visibility
}

// Declared is a value the operator states and the server never checks.
type Declared struct {
	Value  string `json:"value"`
	Source string `json:"source"` // always "operator-declared"
}

func registerEntraStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "entra_status",
		Title: "Entra ID connectivity check",
		Description: "Get an app-only Microsoft Graph token with the certificate and read the tenant's organization. " +
			"Reports the token result, the cloud, and whether directory sync from on-premises is on and when it last ran. " +
			"Then the startup probe (the token's granted permissions, the P1, P2 and Intune licences), the enabled tool " +
			"groups, the visible actions and each hidden action with the reason it is hidden (a missing permission or licence).\n\n" +
			"password_writeback is operator-declared (--entra-password-writeback), not detected: it can't be read over " +
			"app-only Graph. Check it in the Entra admin center under Password reset > On-premises integration.\n\n" +
			"Call this first when another entra_* tool fails: it tells a rejected certificate apart from a Graph " +
			"permission problem.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, EntraStatus, error) {
		e := d.Config.Entra
		out := EntraStatus{Cloud: e.Cloud, Tenant: e.Tenant, GraphURL: e.GraphURL,
			PasswordWriteback: Declared{e.PasswordWriteback, "operator-declared"},
			Probe:             d.EntraProbe, ProbeSkipped: d.Config.NoProbe, Visibility: d.report("entra")}
		exp, err := d.Graph.Token(ctx)
		if err != nil {
			out.Detail = err.Error()
			return &mcp.CallToolResult{IsError: true}, out, nil
		}
		out.Authenticated = true
		out.TokenExpires = exp.UTC().Format(time.RFC3339)
		var org struct {
			Value []struct {
				OnPremisesSyncEnabled      *bool  `json:"onPremisesSyncEnabled"`
				OnPremisesLastSyncDateTime string `json:"onPremisesLastSyncDateTime"`
			} `json:"value"`
		}
		if err := d.Graph.Get(ctx, "/v1.0/organization?$select=id,onPremisesSyncEnabled,onPremisesLastSyncDateTime", &org); err != nil {
			out.Detail = err.Error()
			return &mcp.CallToolResult{IsError: true}, out, nil
		}
		if len(org.Value) > 0 {
			out.OnPremisesSyncEnabled = org.Value[0].OnPremisesSyncEnabled
			out.OnPremisesLastSyncDateTime = org.Value[0].OnPremisesLastSyncDateTime
		}
		return nil, out, nil
	})
}
