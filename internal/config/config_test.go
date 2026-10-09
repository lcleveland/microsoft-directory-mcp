package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secret(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(s+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func noenv(string) string { return "" }

func adArgs(t *testing.T) []string {
	return []string{"--ad-forest", "corp.example.com", "--ad-bind-user", "svc@corp.example.com",
		"--ad-bind-password-file", secret(t, "pw"), "--ad-dc", "dc1.corp.example.com"}
}

func entraArgs(t *testing.T) []string {
	return []string{"--entra-tenant", "00000000-0000-0000-0000-000000000001",
		"--entra-client-id", "00000000-0000-0000-0000-000000000002", "--entra-cert-file", secret(t, "pem")}
}

func TestSides(t *testing.T) {
	c, _, err := Parse(adArgs(t), noenv)
	if err != nil {
		t.Fatal(err)
	}
	if c.AD == nil || c.Entra != nil {
		t.Fatalf("AD only: %+v %+v", c.AD, c.Entra)
	}
	if c.AD.BindPassword != "pw" || c.AD.TLS != "ldaps" || c.AD.DCs[0] != "dc1.corp.example.com" {
		t.Errorf("AD: %+v", c.AD)
	}

	c, _, err = Parse(entraArgs(t), noenv)
	if err != nil {
		t.Fatal(err)
	}
	if c.AD != nil || c.Entra == nil {
		t.Fatalf("Entra only: %+v %+v", c.AD, c.Entra)
	}
	if c.Entra.Cloud != "global" || c.Entra.LoginURL != "https://login.microsoftonline.com" ||
		c.Entra.GraphURL != "https://graph.microsoft.com" || string(c.Entra.CertPEM) != "pem\n" {
		t.Errorf("Entra: %+v", c.Entra)
	}

	c, _, err = Parse(append(adArgs(t), entraArgs(t)...), noenv)
	if err != nil || c.AD == nil || c.Entra == nil {
		t.Fatalf("both: %v", err)
	}
}

func TestNeitherSide(t *testing.T) {
	_, _, err := Parse(nil, noenv)
	if err == nil || !strings.Contains(err.Error(), "neither side") {
		t.Fatalf("got %v", err)
	}
}

func TestEnvMirrors(t *testing.T) {
	env := map[string]string{
		"MSDIR_ENTRA_TENANT":    "00000000-0000-0000-0000-000000000001",
		"MSDIR_ENTRA_CLIENT_ID": "00000000-0000-0000-0000-000000000002",
		"MSDIR_ENTRA_CERT_FILE": secret(t, "pem"),
		"MSDIR_ENTRA_CLOUD":     "usgov",
	}
	c, _, err := Parse(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Entra.LoginURL != "https://login.microsoftonline.us" || c.Entra.GraphURL != "https://graph.microsoft.us" {
		t.Errorf("usgov: %+v", c.Entra)
	}
}

func TestCloudAndURLOverrides(t *testing.T) {
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"--entra-cloud", "china", "--entra-login-url", "http://127.0.0.1:9"}, "mutually exclusive"},
		{[]string{"--entra-cloud", "usgovdod", "--entra-graph-url", "http://127.0.0.1:9"}, "mutually exclusive"},
		{[]string{"--entra-cloud", "mars"}, "unknown cloud"},
		{[]string{"--entra-login-url", "http://login.example.com"}, "https"},
		{[]string{"--entra-graph-url", "ftp://127.0.0.1"}, "https"},
		// global is the default, so naming it does not conflict.
		{[]string{"--entra-cloud", "global", "--entra-login-url", "http://127.0.0.1:9", "--entra-graph-url", "https://graph.example.com/"}, ""},
	} {
		c, _, err := Parse(append(entraArgs(t), tc.args...), noenv)
		if tc.err == "" {
			if err != nil {
				t.Errorf("%v: %v", tc.args, err)
			} else if c.Entra.LoginURL != "http://127.0.0.1:9" || c.Entra.GraphURL != "https://graph.example.com" {
				t.Errorf("%v: %+v", tc.args, c.Entra)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%v: want %q, got %v", tc.args, tc.err, err)
		}
	}
}

func TestSideValidation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"--ad-forest", "corp.example.com", "--ad-dc", "dc1", "--ad-bind-password-file", "/x"}, "--ad-bind-user"},
		{[]string{"--ad-forest", "corp.example.com", "--ad-dc", "dc1", "--ad-bind-user", "u"}, "--ad-bind-password-file"},
		{[]string{"--ad-forest", "corp.example.com", "--ad-bind-user", "u", "--ad-bind-password-file", "/x"}, "--ad-dc"},
		{append(adArgs(t), "--ad-tls", "none"), "--ad-tls"},
		{[]string{"--entra-tenant", "t", "--entra-cert-file", "/x"}, "--entra-client-id"},
		{[]string{"--entra-tenant", "t", "--entra-client-id", "c"}, "--entra-cert-file"},
		{[]string{"--entra-tenant", "t", "--entra-client-id", "c", "--entra-cert-file", "/nonexistent"}, "reading"},
	} {
		if _, _, err := Parse(tc.args, noenv); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%v: want %q, got %v", tc.args, tc.err, err)
		}
	}
}

func TestInsecureSkipVerifyWarns(t *testing.T) {
	c, warnings, err := Parse(append(adArgs(t), "--ad-insecure-skip-verify"), noenv)
	if err != nil {
		t.Fatal(err)
	}
	if !c.AD.InsecureSkipVerify || len(warnings) != 1 || !strings.Contains(warnings[0], "TLS verification disabled") {
		t.Errorf("got %v %v", c.AD.InsecureSkipVerify, warnings)
	}
}

func TestHTTPListener(t *testing.T) {
	tok := secret(t, "bearer")
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"--http"}, ""},
		{[]string{"--http", "--addr", "[::1]:8235"}, ""},
		{[]string{"--http", "--addr", "0.0.0.0:8235"}, "non-loopback"},
		{[]string{"--http", "--addr", "0.0.0.0:8235", "--http-auth-token-file", tok}, ""},
		{[]string{"--http", "--path", "mcp"}, "--path"},
		{[]string{"--http", "--stdio"}, "mutually exclusive"},
	} {
		c, _, err := Parse(append(adArgs(t), tc.args...), noenv)
		if tc.err == "" {
			if err != nil {
				t.Errorf("%v: %v", tc.args, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%v: want %q, got %v (%+v)", tc.args, tc.err, err, c)
		}
	}
	c, _, _ := Parse(append(adArgs(t), "--http", "--http-auth-token-file", tok), noenv)
	if c.HTTPAuthToken != "bearer" {
		t.Errorf("token %q", c.HTTPAuthToken)
	}
}

func TestLogValueHidesSecrets(t *testing.T) {
	c, _, err := Parse(append(append(adArgs(t), entraArgs(t)...), "--http", "--http-auth-token-file", secret(t, "bearer")), noenv)
	if err != nil {
		t.Fatal(err)
	}
	s := c.LogValue().String()
	for _, secret := range []string{"pw", "pem", "bearer"} {
		if strings.Contains(s, "="+secret) || strings.Contains(s, " "+secret) {
			t.Errorf("%q in %s", secret, s)
		}
	}
}
