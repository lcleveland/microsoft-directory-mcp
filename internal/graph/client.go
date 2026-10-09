// Package graph is a small Microsoft Graph client: app-only tokens from a
// certificate assertion, and authenticated requests. See docs/adr/0002.
package graph

import (
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
		graphURL: graphURL, hc: hc, now: time.Now,
	}
	if c.hc == nil {
		c.hc = http.DefaultClient
	}
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
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("graph: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// Get fetches path (e.g. "/v1.0/organization") and decodes the JSON reply
// into out. A 401 fetches a fresh token and retries once.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	for attempt := 0; ; attempt++ {
		tok, _, err := c.bearer(ctx, attempt > 0)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.graphURL+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("graph: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("graph: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode/100 != 2 {
			var env struct {
				Error struct{ Code, Message string } `json:"error"`
			}
			json.Unmarshal(body, &env)
			return &APIError{resp.StatusCode, env.Error.Code, env.Error.Message}
		}
		return json.Unmarshal(body, out)
	}
}
