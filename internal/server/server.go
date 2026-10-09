// Package server builds the MCP server and serves it over stdio or
// streamable HTTP.
package server

import (
	"context"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/tools"
	"github.com/lcleveland/microsoft-directory-mcp/internal/version"
)

// New builds the server with the tools of each configured side.
func New(d tools.Deps, log *slog.Logger) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "microsoft-directory-mcp", Title: "Microsoft directory (AD and Entra ID)", Version: version.Version},
		&mcp.ServerOptions{Logger: log, Instructions: instructions(d)})
	n := tools.Register(s, d)
	log.Info("registered tools", "count", n)
	return s
}

func instructions(d tools.Deps) string {
	s := "Tools for"
	if d.AD != nil {
		s += " the Active Directory forest " + d.Config.AD.Forest
		if d.Graph != nil {
			s += " and"
		}
	}
	if d.Graph != nil {
		s += " the Entra ID tenant " + d.Config.Entra.Tenant
	}
	return s + ".\n\nCall ad_status or entra_status first if anything fails on that side."
}

// ServeStdio runs until ctx is cancelled. Nothing else may write to stdout.
func ServeStdio(ctx context.Context, s *mcp.Server) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}
