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
	Config *config.Config
	AD     *ad.Client    // nil when the AD side is off
	Graph  *graph.Client // nil when the Entra side is off
}

// Register adds the tools of each configured side and returns how many.
// A side that is off has no tools.
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
	Detail     string      `json:"detail,omitempty"`
}

func registerADStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "ad_status",
		Title: "Active Directory connectivity check",
		Description: "Connect to a domain controller over TLS, bind as the service account and read the rootDSE. " +
			"Reports the bind result, the TLS mode, the domain controller used and the naming contexts.\n\n" +
			"Call this first when another ad_* tool fails: it tells an unreachable domain controller, a TLS " +
			"failure and a rejected bind apart.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ADStatus, error) {
		a := d.Config.AD
		out := ADStatus{TLS: a.TLS, Forest: a.Forest, BindUser: a.BindUser}
		if a.InsecureSkipVerify {
			out.TLSWarning = "TLS verification disabled (--ad-insecure-skip-verify)"
		}
		conn, dc, err := d.AD.Dial(ctx)
		out.DC = dc
		if err != nil {
			out.Detail = err.Error()
			return &mcp.CallToolResult{IsError: true}, out, nil
		}
		defer conn.Close()
		out.Bound = true
		if out.RootDSE, err = ad.ReadRootDSE(conn); err != nil {
			out.Detail = err.Error()
			return &mcp.CallToolResult{IsError: true}, out, nil
		}
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
}

func registerEntraStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "entra_status",
		Title: "Entra ID connectivity check",
		Description: "Get an app-only Microsoft Graph token with the certificate and read the tenant's organization. " +
			"Reports the token result, the cloud, and whether directory sync from on-premises is on and when it last ran.\n\n" +
			"Call this first when another entra_* tool fails: it tells a rejected certificate apart from a Graph " +
			"permission problem.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, EntraStatus, error) {
		e := d.Config.Entra
		out := EntraStatus{Cloud: e.Cloud, Tenant: e.Tenant, GraphURL: e.GraphURL}
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
