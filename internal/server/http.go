package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/version"
)

// Handler serves the MCP endpoint, behind a bearer gate when a token is
// configured, plus an unauthenticated /healthz. The SDK rejects loopback
// requests with a non-loopback Host (DNS rebinding); cross-origin browser
// requests are refused here, as the SDK does not check them by default.
func Handler(cfg *config.Config, s *mcp.Server, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok","version":"`+version.Version+`"}`)
	})

	var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Logger: log, SessionTimeout: 10 * time.Minute})
	if cfg.HTTPAuthToken != "" {
		want := []byte(cfg.HTTPAuthToken)
		verify := func(_ context.Context, tok string, _ *http.Request) (*auth.TokenInfo, error) {
			if subtle.ConstantTimeCompare([]byte(tok), want) != 1 {
				return nil, auth.ErrInvalidToken
			}
			return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
		}
		h = auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(h)
	}
	mux.Handle(cfg.Path, h)
	return http.NewCrossOriginProtection().Handler(mux)
}

// ServeHTTP serves on ln until ctx is cancelled (SIGTERM), then drains for up
// to 5s.
func ServeHTTP(ctx context.Context, ln net.Listener, cfg *config.Config, s *mcp.Server, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           Handler(cfg, s, log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", ln.Addr().String(), "path", cfg.Path, "authenticated", cfg.HTTPAuthToken != "")
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
		return <-errc
	}
}
