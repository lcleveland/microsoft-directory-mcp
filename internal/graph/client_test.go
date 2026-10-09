package graph

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	tenant   = "00000000-0000-0000-0000-000000000001"
	clientID = "00000000-0000-0000-0000-000000000002"
	// base64url SHA-256 of testdata/cert.pem's certificate DER, from openssl.
	fixtureX5t = "vnSDhrNPjDt251GqeY_7cou43NFzrkREbfN3O2D6H9o"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newClient(t *testing.T, login, graph string) *Client {
	t.Helper()
	c, err := New(tenant, clientID, fixture(t), login, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func segment(t *testing.T, s string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestAssertion(t *testing.T) {
	c := newClient(t, "https://login.example.com", "https://graph.example.com")
	now := time.Unix(1_800_000_000, 0)
	jwt, err := c.assertion(now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %s", jwt)
	}
	var hdr map[string]string
	segment(t, parts[0], &hdr)
	if hdr["alg"] != "PS256" || hdr["typ"] != "JWT" || hdr["x5t#S256"] != fixtureX5t {
		t.Errorf("header %v", hdr)
	}
	var cl struct {
		Aud, Iss, Sub, Jti string
		Exp, Nbf, Iat      int64
	}
	segment(t, parts[1], &cl)
	if cl.Aud != "https://login.example.com/"+tenant+"/oauth2/v2.0/token" || cl.Iss != clientID || cl.Sub != clientID || cl.Jti == "" {
		t.Errorf("claims %+v", cl)
	}
	if cl.Nbf != now.Unix() || cl.Iat != now.Unix() || cl.Exp <= cl.Nbf || cl.Exp-cl.Nbf > 600 {
		t.Errorf("times %+v", cl)
	}

	// The signature verifies with the fixture certificate's public key.
	var cert *x509.Certificate
	for rest := fixture(t); ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			cert, _ = x509.ParseCertificate(b.Bytes)
		}
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Errorf("signature: %v", err)
	}
	if again, _ := c.assertion(now); again == jwt {
		t.Error("jti repeats")
	}
}

func TestNewRejectsBadPEM(t *testing.T) {
	for name, pemBytes := range map[string][]byte{
		"empty":   nil,
		"no key":  []byte(fixture(t)[strings.Index(string(fixture(t)), "-----BEGIN CERTIFICATE"):]),
		"no cert": []byte(fixture(t)[:strings.Index(string(fixture(t)), "-----BEGIN CERTIFICATE")]),
	} {
		if _, err := New(tenant, clientID, pemBytes, "https://l", "https://g", nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// stub is a token endpoint plus a Graph that answers /v1.0/organization.
type stub struct {
	tokens, calls atomic.Int32
	reject        atomic.Int32 // Graph 401s still to send
	throttle      atomic.Int32 // then Graph 429s still to send
	form          chan map[string][]string
}

func (s *stub) server(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+tenant+"/oauth2/v2.0/token" {
			r.ParseForm()
			select {
			case s.form <- r.PostForm:
			default:
			}
			n := s.tokens.Add(1)
			if r.PostForm.Get("client_id") == "bad" {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS700027: bad assertion"}`)
				return
			}
			io.WriteString(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"tok-`+string(rune('0'+n))+`"}`)
			return
		}
		s.calls.Add(1)
		if s.reject.Load() > 0 {
			s.reject.Add(-1)
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}`)
			return
		}
		if s.throttle.Load() > 0 {
			s.throttle.Add(-1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-"+string(rune('0'+s.tokens.Load())) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"value":[{"onPremisesSyncEnabled":true}]}`)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestTokenRequest(t *testing.T) {
	s := &stub{form: make(chan map[string][]string, 1)}
	ts := s.server(t)
	c := newClient(t, ts.URL, "https://graph.example.com")
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := <-s.form
	for k, want := range map[string]string{
		"client_id":             clientID,
		"grant_type":            "client_credentials",
		"scope":                 "https://graph.example.com/.default",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	} {
		if got := f[k]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want %s", k, got, want)
		}
	}
	if len(f["client_assertion"]) != 1 || strings.Count(f["client_assertion"][0], ".") != 2 {
		t.Errorf("client_assertion %v", f["client_assertion"])
	}
}

func TestTokenError(t *testing.T) {
	s := &stub{}
	ts := s.server(t)
	c, _ := New(tenant, "bad", fixture(t), ts.URL, ts.URL, nil)
	if _, err := c.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "AADSTS700027") {
		t.Errorf("got %v", err)
	}
}

func TestTokenCachedAndRefreshedEarly(t *testing.T) {
	s := &stub{}
	ts := s.server(t)
	c := newClient(t, ts.URL, ts.URL)
	now := time.Now()
	c.now = func() time.Time { return now }
	var out any
	for range 3 {
		if err := c.Get(context.Background(), "/v1.0/organization", &out); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.tokens.Load(); n != 1 {
		t.Errorf("%d token fetches for 3 calls", n)
	}
	// 3599s token: still cached at 54 minutes, refreshed at 56 (5 minutes early).
	now = now.Add(54 * time.Minute)
	c.Get(context.Background(), "/v1.0/organization", &out)
	if n := s.tokens.Load(); n != 1 {
		t.Errorf("refreshed too early: %d", n)
	}
	now = now.Add(2 * time.Minute)
	c.Get(context.Background(), "/v1.0/organization", &out)
	if n := s.tokens.Load(); n != 2 {
		t.Errorf("not refreshed: %d", n)
	}
}

func TestRefetchOnceOn401(t *testing.T) {
	s := &stub{}
	ts := s.server(t)
	c := newClient(t, ts.URL, ts.URL)
	var out struct {
		Value []struct{ OnPremisesSyncEnabled bool }
	}
	s.reject.Store(1)
	if err := c.Get(context.Background(), "/v1.0/organization", &out); err != nil {
		t.Fatal(err)
	}
	if !out.Value[0].OnPremisesSyncEnabled || s.tokens.Load() != 2 || s.calls.Load() != 2 {
		t.Errorf("out %+v tokens %d calls %d", out, s.tokens.Load(), s.calls.Load())
	}
	// A second 401 in a row is an error, not a loop.
	s.reject.Store(2)
	err := c.Get(context.Background(), "/v1.0/organization", &out)
	if err == nil || !strings.Contains(err.Error(), "InvalidAuthenticationToken") || s.calls.Load() != 4 {
		t.Errorf("err %v calls %d", err, s.calls.Load())
	}
}

func TestNoRefetchOn429After401(t *testing.T) {
	s := &stub{}
	ts := s.server(t)
	c := newClient(t, ts.URL, ts.URL)
	s.reject.Store(1)
	s.throttle.Store(2)
	if err := c.Get(context.Background(), "/v1.0/organization", nil); err != nil {
		t.Fatal(err)
	}
	if s.tokens.Load() != 2 || s.calls.Load() != 4 {
		t.Errorf("tokens %d calls %d, want 2 and 4", s.tokens.Load(), s.calls.Load())
	}
}
