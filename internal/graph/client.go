// Package graph is a small Microsoft Graph client: app-only tokens from a
// certificate assertion, and authenticated requests. See docs/adr/0002.
package graph

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hosts are a cloud's login and Graph base URLs.
type Hosts struct{ Login, Graph string }

// Clouds maps --entra-cloud to its fixed host pair.
var Clouds = map[string]Hosts{
	"global":   {"https://login.microsoftonline.com", "https://graph.microsoft.com"},
	"usgov":    {"https://login.microsoftonline.us", "https://graph.microsoft.us"},
	"usgovdod": {"https://login.microsoftonline.us", "https://dod-graph.microsoft.us"},
	"china":    {"https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"},
}

// refreshEarly is how long before expiry a cached token is replaced.
const refreshEarly = 5 * time.Minute

type Client struct {
	clientID string
	key      *rsa.PrivateKey
	x5t      string // base64url SHA-256 of the certificate DER
	tokenURL string
	graphURL string
	hc       *http.Client
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	// cursorKey signs list cursors; random per process.
	cursorKey []byte

	mu    sync.Mutex
	token string
	exp   time.Time
}

// New parses pemBytes (an RSA private key, PKCS#8 or PKCS#1, and its
// certificate). hc nil means http.DefaultClient.
func New(tenant, clientID string, pemBytes []byte, loginURL, graphURL string, hc *http.Client) (*Client, error) {
	c := &Client{
		clientID: clientID,
		tokenURL: loginURL + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token",
		graphURL: graphURL, hc: hc, now: time.Now, sleep: sleep,
	}
	if c.hc == nil {
		c.hc = http.DefaultClient
	}
	c.cursorKey = make([]byte, 32)
	rand.Read(c.cursorKey)
	for rest := pemBytes; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			if c.x5t == "" {
				sum := sha256.Sum256(b.Bytes)
				c.x5t = base64.RawURLEncoding.EncodeToString(sum[:])
			}
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("entra certificate file: %w", err)
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("entra certificate file: the key must be RSA (PS256)")
			}
			c.key = rk
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("entra certificate file: %w", err)
			}
			c.key = k
		}
	}
	if c.key == nil || c.x5t == "" {
		return nil, errors.New("entra certificate file: want an unencrypted RSA private key and a certificate in PEM")
	}
	return c, nil
}

// assertion is the client_assertion JWT: PS256, x5t#S256, aud the token URL.
func (c *Client) assertion(now time.Time) (string, error) {
	jti := make([]byte, 16)
	rand.Read(jti)
	hdr, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": c.x5t})
	claims, _ := json.Marshal(map[string]any{
		"aud": c.tokenURL, "iss": c.clientID, "sub": c.clientID,
		"jti": fmt.Sprintf("%x-%x-%x-%x-%x", jti[0:4], jti[4:6], jti[6:8], jti[8:10], jti[10:]),
		"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, c.key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Token returns when the current token expires, fetching one if none is
// cached or it is within refreshEarly of expiry.
func (c *Client) Token(ctx context.Context) (time.Time, error) {
	_, exp, err := c.bearer(ctx, false)
	return exp, err
}

func (c *Client) bearer(ctx context.Context, force bool) (string, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !force && c.token != "" && now.Before(c.exp.Add(-refreshEarly)) {
		return c.token, c.exp, nil
	}
	jwt, err := c.assertion(now)
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{
		"client_id":             {c.clientID},
		"scope":                 {c.graphURL + "/.default"},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil && resp.StatusCode == http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("token request: HTTP %d %s: %s", resp.StatusCode, body.Error, body.Description)
	}
	c.token, c.exp = body.AccessToken, now.Add(time.Duration(body.ExpiresIn)*time.Second)
	return c.token, c.exp, nil
}

// APIError is a non-2xx Graph reply.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("graph: HTTP %d %s: %s", e.Status, e.Code, e.Message)
	if e.RequestID != "" {
		s += " (request-id " + e.RequestID + ")"
	}
	return s
}

func apiError(status int, body []byte) *APIError {
	var env struct {
		Error struct {
			Code, Message string
			InnerError    struct {
				RequestID string `json:"request-id"`
			} `json:"innerError"`
		} `json:"error"`
	}
	json.Unmarshal(body, &env)
	return &APIError{status, env.Error.Code, env.Error.Message, env.Error.InnerError.RequestID}
}

// Get fetches path (e.g. "/v1.0/organization") and decodes the JSON reply
// into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Do sends method to path with body JSON-encoded (nil for none) and decodes
// the reply into out (nil discards it).
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	resp, err := c.send(ctx, method, c.graphURL+path, false, b)
	if err != nil || out == nil || len(resp) == 0 {
		return err
	}
	return json.Unmarshal(resp, out)
}

const (
	maxRetries = 3
	maxWait    = time.Minute
)

// send makes one request. A 401 fetches a fresh token and retries once. A
// GET answered 429 or 503 waits out Retry-After and retries, unless the wait
// is over maxWait or would outlast ctx's deadline; other methods are never
// retried.
func (c *Client) send(ctx context.Context, method, u string, eventual bool, body []byte) ([]byte, error) {
	force := false
	for retries := 0; ; {
		tok, _, err := c.bearer(ctx, force)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if eventual {
			req.Header.Set("ConsistencyLevel", "eventual")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("graph: %w", err)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("graph: %w", err)
		}
		switch st := resp.StatusCode; {
		case st/100 == 2:
			return b, nil
		case st == http.StatusUnauthorized && !force:
			force = true
			continue
		case method == http.MethodGet && (st == http.StatusTooManyRequests || st == http.StatusServiceUnavailable) && retries < maxRetries:
			wait := retryAfter(resp.Header, retries)
			if dl, ok := ctx.Deadline(); wait <= maxWait && (!ok || time.Until(dl) > wait) {
				retries++
				if err := c.sleep(ctx, wait); err != nil {
					return nil, err
				}
				continue
			}
		}
		return nil, apiError(resp.StatusCode, b)
	}
}

// retryAfter reads Retry-After in seconds, else backs off exponentially.
func retryAfter(h http.Header, retries int) time.Duration {
	secs, err := strconv.Atoi(h.Get("Retry-After"))
	if err != nil || secs < 0 {
		return time.Second << retries
	}
	return time.Duration(secs) * time.Second
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
