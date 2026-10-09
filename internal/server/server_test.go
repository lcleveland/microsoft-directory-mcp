package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
	"github.com/lcleveland/microsoft-directory-mcp/internal/tools"
)

var discard = slog.New(slog.DiscardHandler)

// entraOnly builds a server with the Entra side on, against a Graph stub.
func entraOnly(t *testing.T, cfg *config.Config) *mcp.Server {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"tok","expires_in":3599}`)
			return
		}
		io.WriteString(w, `{"value":[{"onPremisesSyncEnabled":true,"onPremisesLastSyncDateTime":"2026-01-01T00:00:00Z"}]}`)
	}))
	t.Cleanup(stub.Close)
	pemBytes, err := os.ReadFile("../graph/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.New("tenant", "client", pemBytes, stub.URL, stub.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Path = "/mcp"
	cfg.Entra = &config.Entra{Tenant: "tenant", Cloud: "global", GraphURL: stub.URL}
	return New(tools.Deps{Config: cfg, Graph: g}, discard)
}

type bearer struct {
	tok  string
	next http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.next.RoundTrip(r)
}

func connect(url, tok string) (*mcp.ClientSession, error) {
	hc := http.DefaultClient
	if tok != "" {
		hc = &http.Client{Transport: bearer{tok, http.DefaultTransport}}
	}
	return mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: url + "/mcp", HTTPClient: hc}, nil)
}

// check asserts only entra_status is listed and that calling it succeeds.
func check(t *testing.T, cs *mcp.ClientSession) {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	// The AD side is off, so ad_status does not exist.
	if !slices.Equal(names, []string{"entra_status"}) {
		t.Errorf("tools %v", names)
	}
	out, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "entra_status"})
	if err != nil || out.IsError {
		t.Fatalf("entra_status: %v %+v", err, out)
	}
	sc := out.StructuredContent.(map[string]any)
	if sc["authenticated"] != true || sc["on_premises_sync_enabled"] != true {
		t.Errorf("entra_status %v", sc)
	}
}

func TestStdio(t *testing.T) {
	s := entraOnly(t, &config.Config{})
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx, &mcp.IOTransport{Reader: sr, Writer: sw})
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(ctx, &mcp.IOTransport{Reader: cr, Writer: cw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if got := cs.InitializeResult().ServerInfo.Name; got != "microsoft-directory-mcp" {
		t.Errorf("server name %q", got)
	}
	check(t, cs)
}

func TestHTTP(t *testing.T) {
	cfg := &config.Config{}
	ts := httptest.NewServer(Handler(cfg, entraOnly(t, cfg), discard))
	defer ts.Close()
	cs, err := connect(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	check(t, cs)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok"`) {
		t.Errorf("healthz: %d %s", resp.StatusCode, b)
	}
}

func TestHTTPBearer(t *testing.T) {
	cfg := &config.Config{HTTPAuthToken: "right-token"}
	ts := httptest.NewServer(Handler(cfg, entraOnly(t, cfg), discard))
	defer ts.Close()
	for _, tok := range []string{"", "wrong-token"} {
		if cs, err := connect(ts.URL, tok); err == nil {
			cs.Close()
			t.Errorf("token %q accepted", tok)
		}
	}
	cs, err := connect(ts.URL, "right-token")
	if err != nil {
		t.Fatal(err)
	}
	cs.Close()
	// healthz stays open for liveness probes.
	if resp, err := http.Get(ts.URL + "/healthz"); err != nil || resp.StatusCode != 200 {
		t.Errorf("healthz behind auth: %v %v", resp, err)
	}
}
