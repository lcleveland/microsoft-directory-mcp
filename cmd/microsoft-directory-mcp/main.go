// Command microsoft-directory-mcp is an MCP server for one Active Directory
// forest and one Entra ID tenant.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
	"github.com/lcleveland/microsoft-directory-mcp/internal/server"
	"github.com/lcleveland/microsoft-directory-mcp/internal/tools"
	"github.com/lcleveland/microsoft-directory-mcp/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "microsoft-directory-mcp:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, warnings, err := config.Parse(args, os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.ShowVersion {
		fmt.Println(version.Version)
		return nil
	}
	// stdout belongs to the stdio transport; logs go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	for _, w := range warnings {
		log.Warn(w)
	}
	log.Info("starting", "version", version.Version, "config", cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	d := tools.Deps{Config: cfg}
	if cfg.AD != nil {
		if d.AD, err = ad.New(cfg.AD, cfg.RequestTimeout); err != nil {
			return err
		}
	}
	if e := cfg.Entra; e != nil {
		if d.Graph, err = graph.New(e.Tenant, e.ClientID, e.CertPEM, e.LoginURL, e.GraphURL, &http.Client{Timeout: cfg.RequestTimeout}); err != nil {
			return err
		}
	}
	// The tool list is fixed at startup, so the probe runs once, before it.
	if !cfg.NoProbe {
		if d.AD != nil {
			d.ADProbe = d.AD.Probe(ctx)
			log.Info("AD probe", "bound", d.ADProbe.Bound, "domains", len(d.ADProbe.Domains), "reads", d.ADProbe.Reads, "note", d.ADProbe.Note)
		}
		if d.Graph != nil {
			d.EntraProbe = d.Graph.Probe(ctx)
			log.Info("Entra probe", "roles", len(d.EntraProbe.Roles), "licences", d.EntraProbe.Licences, "notes", d.EntraProbe.Notes)
		}
	}
	s := server.New(d, log)
	if cfg.HTTP {
		ln, err := net.Listen("tcp", cfg.Addr)
		if err != nil {
			return err
		}
		return server.ServeHTTP(ctx, ln, cfg, s, log)
	}
	return server.ServeStdio(ctx, s)
}
