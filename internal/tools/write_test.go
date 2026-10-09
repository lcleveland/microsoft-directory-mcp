package tools

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
)

func TestClassifyAD(t *testing.T) {
	old := adObjectAttrs
	adObjectAttrs = map[string][]string{"user": {"description"}}
	t.Cleanup(func() { adObjectAttrs = old })
	for _, tc := range []struct {
		op, attr, class string
		raw             bool
		want, refused   string // the capability, or what the refusal says
	}{
		{"modify", "userAccountControl", "user", false, "ad-account-state", ""},
		{"modify", "USERACCOUNTCONTROL", "computer", false, "ad-account-state", ""},
		{"modify", "lockoutTime", "user", false, "ad-account-state", ""},
		{"modify", "pwdLastSet", "user", false, "ad-account-state", ""},
		{"modify", "accountExpires", "user", false, "ad-account-state", ""},
		{"modify", "unicodePwd", "user", false, "ad-passwords", ""},
		{"modify", "member", "group", false, "ad-group-membership", ""},
		{"delete", "", "user", false, "ad-delete", ""},
		// Raw: a first-class write is routed to its action.
		{"modify", "userAccountControl", "user", true, "", "call ad_user or ad_computer disable or enable instead"},
		{"modify", "unicodePwd", "user", true, "", "call ad_user reset_password instead (the ad-passwords capability)"},
		{"modify", "gPLink", "organizationalUnit", true, "", "call ad_gpo link instead"},
		{"modify", "gPOptions", "organizationalUnit", true, "", "call ad_gpo block_inheritance instead (the ad-gpo-links capability)"},
		{"modify", "gPLink", "organizationalUnit", false, "ad-gpo-links", ""},
		{"modify", "msDS-PSOAppliesTo", "msDS-PasswordSettings", false, "ad-password-policy", ""},
		{"modify", "msDS-LockoutThreshold", "msDS-PasswordSettings", false, "ad-password-policy", ""},
		{"modify", "msDS-MinimumPasswordLength", "msDS-PasswordSettings", true, "", "call ad_policy edit instead"},
		{"modify", "description", "msDS-PasswordSettings", false, "", "not a write this server makes"},
		{"add", "", "", true, "", "call ad_user, ad_group or ad_computer create instead"},
		{"delete", "", "", true, "", "call ad_object delete instead"},
		{"rename", "", "", true, "", "call ad_object rename or move instead"},
		// Raw: the ad-objects allowlist, by class, and nothing else.
		{"modify", "description", "user", true, "ad-objects", ""},
		{"modify", "description", "group", true, "", "not a write this server makes"},
		{"modify", "servicePrincipalName", "user", true, "", "not a write this server makes"},
		{"modify", "description", "user", false, "", "not a write this server makes"},
	} {
		got, err := classifyAD(tc.op, tc.attr, tc.class, tc.raw)
		if tc.refused == "" && (err != nil || got != tc.want) || tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)) {
			t.Errorf("%s %s on %s raw=%v: %q %v", tc.op, tc.attr, tc.class, tc.raw, got, err)
		}
	}
}

// writeDeps is Deps with an audit log in buf, capabilities caps and the
// transport stubbed: the target pre-reads as e, and the modifies vet
// returned, i.e. what would have been sent, are recorded.
func writeDeps(t *testing.T, e *ldap.Entry, caps ...string) (Deps, *bytes.Buffer, *[]any) {
	t.Helper()
	a, err := ad.New(&config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var sent []any
	old, oldA := adModify, adAdd
	adModify = func(_ *ad.Client, _ context.Context, dn, _ string, _ []string, vet func(*ldap.Entry) (any, error)) (ad.Target, error) {
		if !strings.EqualFold(dn, e.DN) {
			t.Errorf("wrote %s, want %s", dn, e.DN)
		}
		req, err := vet(e)
		if err == nil {
			sent = append(sent, req)
		}
		return ad.Target{DC: "dc2.corp.example.com:636"}, err
	}
	adAdd = func(_ *ad.Client, _ context.Context, req *ldap.AddRequest) (ad.Target, error) {
		sent = append(sent, req)
		return ad.Target{DC: "dc2.corp.example.com:636"}, nil
	}
	oldP, oldG := adProtected, adGet
	adProtected = func(*ad.Client, context.Context, string) (string, error) { return "", nil }
	adGet = func(_ *ad.Client, _ context.Context, id, _ string, _ []string) (*ldap.Entry, error) {
		return ldap.NewEntry(id, nil), nil
	}
	t.Cleanup(func() { adModify, adAdd, adProtected, adGet = old, oldA, oldP, oldG })
	c := map[string]bool{}
	for _, x := range caps {
		c[x] = true
	}
	buf := &bytes.Buffer{}
	return Deps{Config: &config.Config{Capabilities: c}, AD: a, Log: slog.New(slog.NewTextHandler(buf, nil))}, buf, &sent
}

const ada = "CN=ada,CN=Users,DC=corp,DC=example,DC=com"

func adaEntry(extra map[string][]string) *ldap.Entry {
	attrs := map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
		"sAMAccountName": {"ada"}, "userAccountControl": {"66048"}}
	for k, v := range extra {
		attrs[k] = v
	}
	return ldap.NewEntry(ada, attrs)
}

func run(d Deps, x adExtra, in adIn) (map[string]any, error) {
	return x.run(d, context.Background(), in)
}

// Disable flips only ACCOUNTDISABLE, as a compare-and-swap, and the audit
// log has the reason, target, capability, DC and outcome.
func TestDisableWrites(t *testing.T) {
	d, buf, sent := writeDeps(t, adaEntry(nil), "ad-account-state")
	out, err := run(d, accountState("ad_user", adUsers, "disable"), adIn{ID: ada, writeIn: writeIn{Reason: " ticket 42 "}})
	if err != nil {
		t.Fatal(err)
	}
	if out["dc"] != "dc2.corp.example.com:636" || out["dn"] != ada || out["action"] != "disable" || out["fallback"] != nil {
		t.Errorf("reply %v", out)
	}
	if len(*sent) != 1 {
		t.Fatalf("sent %d", len(*sent))
	}
	got := fmt.Sprint((*sent)[0].(*ldap.ModifyRequest).Changes)
	if want := fmt.Sprint([]ldap.Change{
		{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "userAccountControl", Vals: []string{"66048"}}},
		{Operation: ldap.AddAttribute, Modification: ldap.PartialAttribute{Type: "userAccountControl", Vals: []string{"66050"}}},
	}); got != want {
		t.Errorf("changes %s, want %s", got, want)
	}
	log := buf.String()
	for _, want := range []string{`reason="ticket 42"`, "target=" + `"` + ada, "capability=ad-account-state", "dc=dc2.corp.example.com:636",
		"outcome=sending", "outcome=ok", "attributes=[userAccountControl]"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log lacks %s:\n%s", want, log)
		}
	}
	if strings.Contains(log, "66050") {
		t.Errorf("a value reached the audit log:\n%s", log)
	}
}

// Everything that refuses a write refuses before sending.
func TestWriteRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry *ldap.Entry
		caps  []string
		w     func(Deps) (map[string]any, error)
		says  string
	}{
		{"no reason", adaEntry(nil), []string{"ad-account-state"}, func(d Deps) (map[string]any, error) {
			return run(d, accountState("ad_user", adUsers, "enable"), adIn{ID: ada, writeIn: writeIn{Reason: "  "}})
		}, "reason is required"},
		{"capability off", adaEntry(nil), []string{"ad-objects"}, func(d Deps) (map[string]any, error) {
			return run(d, accountState("ad_user", adUsers, "unlock"), adIn{ID: ada, writeIn: writeIn{Reason: "r"}})
		}, "needs the ad-account-state capability"},
		{"confirm mismatch", adaEntry(nil), []string{"ad-account-state"}, func(d Deps) (map[string]any, error) {
			return d.adWrite(context.Background(), adWrite{tool: "ad_user", action: "x", id: ada, class: adUsers.class, confirm: true,
				in: writeIn{Reason: "r", Confirm: "bob"}, changes: func(*ldap.Entry) ([]ldap.Change, error) { t.Error("built changes"); return nil, nil }})
		}, `confirm must be the target's name exactly: ` + ada + ` is "ada"`},
		{"msDS-ObjectSoa Cloud", adaEntry(map[string][]string{"msDS-ObjectSoa": {"Cloud"}}), []string{"ad-account-state"}, func(d Deps) (map[string]any, error) {
			return run(d, accountState("ad_user", adUsers, "disable"), adIn{ID: ada, writeIn: writeIn{Reason: "r"}})
		}, "managed in the tenant (msDS-ObjectSoa says so)"},
		{"raw unicodePwd", adaEntry(nil), []string{"ad-account-state", "ad-objects"}, func(d Deps) (map[string]any, error) {
			return d.apiModify(context.Background(), adAPIIn{DN: ada, writeIn: writeIn{Reason: "r"},
				Changes: []adChange{{Op: "replace", Attribute: "unicodePwd", Values: []string{"secret"}}}})
		}, "call ad_user reset_password instead"},
		{"raw unmapped", adaEntry(nil), []string{"ad-objects"}, func(d Deps) (map[string]any, error) {
			return d.apiModify(context.Background(), adAPIIn{DN: ada, writeIn: writeIn{Reason: "r"},
				Changes: []adChange{{Op: "add", Attribute: "servicePrincipalName", Values: []string{"HTTP/x"}}}})
		}, "not a write this server makes"},
		{"bad expiry", adaEntry(nil), []string{"ad-account-state"}, func(d Deps) (map[string]any, error) {
			return run(d, accountState("ad_user", adUsers, "set_expiry"), adIn{ID: ada, Expires: "tomorrow", writeIn: writeIn{Reason: "r"}})
		}, "want an RFC 3339 time"},
	} {
		d, buf, sent := writeDeps(t, tc.entry, tc.caps...)
		_, err := tc.w(d)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if len(*sent) != 0 {
			t.Errorf("%s: sent %v", tc.name, (*sent)[0])
		}
		if strings.Contains(buf.String(), "secret") {
			t.Errorf("%s: a value reached the audit log", tc.name)
		}
	}
}

// A synced target's reply says when Entra follows; a cloud-managed
// counterpart refuses the write.
func TestWriteSourceOfAuthority(t *testing.T) {
	sidB, _ := ad.SIDBytes(testSID)
	e := adaEntry(map[string][]string{"objectSid": {string(sidB)}})
	for _, tc := range []struct {
		cloud bool
		want  string
	}{{false, "reaches its Entra counterpart u1 on the next sync cycle"}, {true, "managed in the tenant"}} {
		d, _, sent := writeDeps(t, e, "ad-account-state")
		g, _ := graphStub(t, func(r *http.Request) string {
			if strings.HasSuffix(r.URL.Path, "/onPremisesSyncBehavior") {
				return fmt.Sprintf(`{"isCloudManaged":%v}`, tc.cloud)
			}
			return `{"value":[{"id":"u1","onPremisesSyncEnabled":true}]}`
		})
		d.Graph = g
		out, err := run(d, accountState("ad_user", adUsers, "unlock"), adIn{ID: ada, writeIn: writeIn{Reason: "r"}})
		if got := fmt.Sprint(out["sync"], err); !strings.Contains(got, tc.want) {
			t.Errorf("cloud=%v: %s", tc.cloud, got)
		}
		if n := len(*sent); n != map[bool]int{false: 1, true: 0}[tc.cloud] {
			t.Errorf("cloud=%v: sent %d", tc.cloud, n)
		}
	}
}

func TestFileTime(t *testing.T) {
	for in, want := range map[string]string{
		"never":                "9223372036854775807",
		"1601-01-01T00:00:00Z": "0",
		"2026-01-01T00:00:00Z": "134116992000000000",
	} {
		if got, err := fileTime(in); err != nil || got != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
}

// Generated passwords meet AD complexity for the account and never reach
// a logger, however they are logged.
func TestNewPassword(t *testing.T) {
	for _, n := range []int{0, 20, 64} {
		for range 200 {
			pw := newPassword(n, "jdoe", "Doe, Jane")
			if len(pw) != max(n, 20) || !complexEnough(string(pw), []string{"jdoe", "Doe, Jane"}) {
				t.Fatalf("n=%d: %q", n, string(pw))
			}
		}
	}
	if complexEnough("Aa1!xxxjanexxxxxxxxx", []string{"Doe, Jane"}) || complexEnough("aa1!xxxxxxxxxxxxxxxx", nil) {
		t.Error("complexEnough passes a name part or a missing class")
	}
	pw := newPassword(20)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("reset", "password", pw, "all", []any{pw})
	log.Info(fmt.Sprint("set ", pw), slog.Any("pw", pw), "map", map[string]any{"pw": pw})
	slog.New(slog.NewTextHandler(&buf, nil)).Info("text", "all", []any{pw}, "pw", pw)
	if strings.Contains(buf.String(), string(pw)) || !strings.Contains(buf.String(), "[redacted]") {
		t.Errorf("logged: %s", buf.String())
	}
}

// With ad-account-state on, the real roster shows its writes and the
// write parameters; ad_api shows modify but not ad-delete's delete, and
// refuses delete if called.
func TestAccountStateRegisters(t *testing.T) {
	cs := writeSession(t, "ad-account-state")
	ctx := context.Background()
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"ad_user":     {"search", "get", "resultant_policy", "lockout", "disable", "enable", "unlock", "must_change", "set_expiry"},
		"ad_computer": {"search", "get", "disable", "enable", "set_expiry"},
		"ad_api":      {"search", "modify"},
		"ad_group":    {"search", "get", "members"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: %v, want %v", name, got[name], want)
		}
	}
	for name, want := range map[string][]string{
		"ad_user":     {"reason", "expires"},
		"ad_computer": {"reason", "expires"},
		"ad_api":      {"reason", "dn", "changes"},
	} {
		p := props(t, cs, name)
		for _, w := range want {
			if !slices.Contains(p, w) {
				t.Errorf("%s lacks %s: %v", name, w, p)
			}
		}
		if slices.Contains(p, "confirm") {
			t.Errorf("%s shows a parameter of a write it lacks: %v", name, p)
		}
	}
	if p := props(t, cs, "ad_group"); slices.Contains(p, "reason") {
		t.Errorf("ad_group, with no write, has reason: %v", p)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "ad_api", Arguments: map[string]any{"action": "delete", "dn": ada, "reason": "r"}})
	if err != nil || !res.IsError {
		t.Errorf("ad_api delete ran: %v %+v", err, res)
	}
}

// A reset sets a generated password, with must-change unless turned off,
// under ad-passwords alone; the reply returns it once and the audit log
// never has it.
func TestResetPassword(t *testing.T) {
	for _, keep := range []bool{false, true} {
		d, buf, sent := writeDeps(t, adaEntry(map[string][]string{"displayName": {"Ada Lovelace"}}), "ad-passwords")
		in := adIn{ID: ada, writeIn: writeIn{Reason: "r", Confirm: "ada"}}
		if keep {
			in.MustChange = new(false)
		}
		out, err := run(d, resetPassword, in)
		if err != nil {
			t.Fatal(err)
		}
		pw, _ := out["password"].(string)
		if len(pw) < 20 || !complexEnough(pw, []string{"ada", "Ada Lovelace"}) || out["must_change"] != !keep || out["dc"] == nil {
			t.Errorf("keep=%v: reply %v", keep, out)
		}
		if len(*sent) != 1 {
			t.Fatalf("sent %d", len(*sent))
		}
		var quoted []byte
		for _, c := range `"` + pw + `"` {
			quoted = append(quoted, byte(c), 0)
		}
		want := []ldap.Change{{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "unicodePwd", Vals: []string{string(quoted)}}}}
		if !keep {
			want = append(want, ldap.Change{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "pwdLastSet", Vals: []string{"0"}}})
		}
		if got := (*sent)[0].(*ldap.ModifyRequest).Changes; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("keep=%v: changes %v", keep, got)
		}
		log := buf.String()
		if strings.Contains(log, pw) || !strings.Contains(log, "capability=ad-passwords") || !strings.Contains(log, "outcome=ok") {
			t.Errorf("keep=%v: audit log:\n%s", keep, log)
		}
	}
}

// Membership writes add or remove up to 20 members in one permissive
// modify of the group.
func TestMembers(t *testing.T) {
	const team = "CN=team,CN=Users,DC=corp,DC=example,DC=com"
	g := ldap.NewEntry(team, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"team"}})
	for _, tc := range []struct {
		action string
		op     uint
	}{{"add_members", ldap.AddAttribute}, {"remove_members", ldap.DeleteAttribute}} {
		d, buf, sent := writeDeps(t, g, "ad-group-membership")
		out, err := d.membership(context.Background(), adGroupIn{adIn: adIn{ActionParam: ActionParam{tc.action}, ID: team,
			writeIn: writeIn{Reason: "r"}}, Members: []string{ada, ada}})
		if err != nil {
			t.Fatal(err)
		}
		if out["action"] != tc.action || len(*sent) != 1 {
			t.Fatalf("%s: %v, sent %d", tc.action, out, len(*sent))
		}
		req := (*sent)[0].(*ldap.ModifyRequest)
		want := []ldap.Change{{Operation: tc.op, Modification: ldap.PartialAttribute{Type: "member", Vals: []string{ada}}}}
		if fmt.Sprint(req.Changes) != fmt.Sprint(want) || len(req.Controls) != 1 || req.Controls[0].GetControlType() != ldap.ControlTypeMicrosoftPermissiveModify {
			t.Errorf("%s: %v %v", tc.action, req.Changes, req.Controls)
		}
		if !strings.Contains(buf.String(), "capability=ad-group-membership") {
			t.Errorf("%s: audit log:\n%s", tc.action, buf.String())
		}
	}
}

// Every membership and reset refusal refuses before sending.
func TestMemberAndResetRefusals(t *testing.T) {
	const team = "CN=team,CN=Users,DC=corp,DC=example,DC=com"
	g := ldap.NewEntry(team, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"team"}})
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf("CN=u%d,CN=Users,DC=corp,DC=example,DC=com", i)
	}
	add := func(members ...string) func(Deps) (map[string]any, error) {
		return func(d Deps) (map[string]any, error) {
			return d.membership(context.Background(), adGroupIn{adIn: adIn{ActionParam: ActionParam{"add_members"}, ID: team,
				writeIn: writeIn{Reason: "r"}}, Members: members})
		}
	}
	for _, tc := range []struct {
		name  string
		entry *ldap.Entry
		w     func(Deps) (map[string]any, error)
		says  string
	}{
		{"no members", g, add(), "1 to 20 members"},
		{"21 members", g, add(many...), "1 to 20 members"},
		{"protected member", g, add(ada, "CN=Administrator,CN=Users,DC=corp,DC=example,DC=com"), "whatever capabilities are enabled: RID 500"},
		{"no reason", g, func(d Deps) (map[string]any, error) {
			return d.membership(context.Background(), adGroupIn{adIn: adIn{ActionParam: ActionParam{"add_members"}, ID: team}, Members: []string{ada}})
		}, "reason is required"},
		{"reset without confirm", adaEntry(nil), func(d Deps) (map[string]any, error) {
			return run(d, resetPassword, adIn{ID: ada, writeIn: writeIn{Reason: "r"}})
		}, "confirm must be the target's name exactly"},
		{"reset confirm mismatch", adaEntry(nil), func(d Deps) (map[string]any, error) {
			return run(d, resetPassword, adIn{ID: ada, writeIn: writeIn{Reason: "r", Confirm: "Ada"}})
		}, "confirm must be the target's name exactly"},
	} {
		d, _, sent := writeDeps(t, tc.entry, "ad-passwords", "ad-group-membership")
		adProtected = func(_ *ad.Client, _ context.Context, dn string) (string, error) {
			if strings.HasPrefix(dn, "CN=Administrator,") {
				return "RID 500", nil
			}
			return "", nil
		}
		_, err := tc.w(d)
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if len(*sent) != 0 {
			t.Errorf("%s: sent %v", tc.name, (*sent)[0])
		}
	}
}

// writeSession is a client session of the real roster, every group on,
// with capabilities caps.
func writeSession(t *testing.T, caps ...string) *mcp.ClientSession {
	t.Helper()
	cfg := &config.Config{ToolGroups: map[string]bool{}, Capabilities: map[string]bool{},
		AD: &config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}}
	for _, g := range config.Groups {
		cfg.ToolGroups[g] = true
	}
	for _, c := range caps {
		cfg.Capabilities[c] = true
	}
	a, err := ad.New(cfg.AD, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "t"}, nil)
	Register(s, Deps{Config: cfg, AD: a})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// With ad-passwords and ad-group-membership on, ad_user shows
// reset_password with confirm and must_change, and ad_group its
// membership writes with members.
func TestPasswordsAndMembershipRegister(t *testing.T) {
	cs := writeSession(t, "ad-passwords", "ad-group-membership")
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"ad_user":  {"search", "get", "resultant_policy", "lockout", "reset_password"},
		"ad_group": {"search", "get", "members", "add_members", "remove_members"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: %v, want %v", name, got[name], want)
		}
	}
	for name, want := range map[string][]string{"ad_user": {"reason", "confirm", "must_change"}, "ad_group": {"reason", "members"}} {
		p := props(t, cs, name)
		for _, w := range want {
			if !slices.Contains(p, w) {
				t.Errorf("%s lacks %s: %v", name, w, p)
			}
		}
		if slices.Contains(p, "expires") || name == "ad_group" && slices.Contains(p, "confirm") {
			t.Errorf("%s shows a parameter of a write it lacks: %v", name, p)
		}
	}
}

// The ad-objects allowlist is descriptive only, per class: nothing that
// grants access, delegates, or changes sign-in is ever on it, and ad_api
// and ad_object edit refuse anything off it.
func TestObjectAllowlist(t *testing.T) {
	for class, attrs := range adObjectAttrs {
		for _, never := range []string{"userAccountControl", "servicePrincipalName", "msDS-KeyCredentialLink", "sIDHistory",
			"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo", "nTSecurityDescriptor", "adminCount",
			"unicodePwd", "primaryGroupID", "userPrincipalName", "scriptPath", "member", "groupType"} {
			if slices.ContainsFunc(attrs, func(a string) bool { return strings.EqualFold(a, never) }) {
				t.Errorf("%s allows %s", class, never)
			}
		}
	}
	for _, tc := range []struct {
		class, attr string
		ok          bool
	}{{"user", "title", true}, {"user", "TITLE", true}, {"group", "title", false}, {"group", "description", true},
		{"computer", "location", true}, {"computer", "title", false}, {"organizationalUnit", "description", false}} {
		_, err := classifyAD("modify", tc.attr, tc.class, true)
		if (err == nil) != tc.ok {
			t.Errorf("%s on %s: %v", tc.attr, tc.class, err)
		}
	}
	for _, attrs := range []map[string]string{{"title": "x", "servicePrincipalName": "HTTP/x"}, {"userAccountControl": "512"}} {
		d, _, sent := writeDeps(t, adaEntry(nil), "ad-objects", "ad-account-state")
		if _, err := d.edit(context.Background(), adIn{ID: ada, Attributes: attrs, writeIn: writeIn{Reason: "r"}}); err == nil || len(*sent) != 0 {
			t.Errorf("edit %v: %v, sent %d", attrs, err, len(*sent))
		}
	}
	d, _, sent := writeDeps(t, adaEntry(nil), "ad-objects")
	if _, err := d.edit(context.Background(), adIn{ID: ada, Attributes: map[string]string{"title": "Engineer", "info": ""},
		writeIn: writeIn{Reason: "r"}}); err != nil || len(*sent) != 1 {
		t.Fatalf("edit: %v", err)
	}
	if got, want := fmt.Sprint((*sent)[0].(*ldap.ModifyRequest).Changes), fmt.Sprint([]ldap.Change{
		{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "info"}},
		{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "title", Vals: []string{"Engineer"}}},
	}); got != want {
		t.Errorf("changes %s, want %s", got, want)
	}
}

// A created user gets a generated password, must change it, and is
// enabled, in one add; the reply returns the password once and the audit
// log never has it. Off-allowlist attributes refuse the create.
func TestCreate(t *testing.T) {
	d, buf, sent := writeDeps(t, adaEntry(nil), "ad-objects")
	const ou = "OU=Staff,DC=corp,DC=example,DC=com"
	out, err := d.create(context.Background(), "ad_user", "user", adIn{Parent: ou, Name: "Grace, H", Sam: "grace", UPN: "grace@example.com",
		Attributes: map[string]string{"displayName": "Grace Hopper"}, writeIn: writeIn{Reason: "r"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := out["password"].(string)
	if out["dn"] != `CN=Grace\, H,`+ou || out["must_change"] != true || len(pw) < 20 || out["dc"] == nil {
		t.Errorf("reply %v", out)
	}
	req := (*sent)[0].(*ldap.AddRequest)
	got := map[string][]string{}
	for _, a := range req.Attributes {
		got[a.Type] = a.Vals
	}
	if got["sAMAccountName"][0] != "grace" || got["userAccountControl"][0] != "512" || got["pwdLastSet"][0] != "0" ||
		got["userPrincipalName"][0] != "grace@example.com" || got["unicodePwd"][0] != unicodePwd(secret(pw)) || got["displayName"][0] != "Grace Hopper" {
		t.Errorf("add %v", got)
	}
	if log := buf.String(); strings.Contains(log, pw) || !strings.Contains(log, "capability=ad-objects") || !strings.Contains(log, "outcome=ok") {
		t.Errorf("audit log:\n%s", log)
	}

	_, err = d.create(context.Background(), "ad_group", "group", adIn{Parent: ou, Name: "team", writeIn: writeIn{Reason: "r"}}, "-2147483646")
	req = (*sent)[1].(*ldap.AddRequest)
	if err != nil || fmt.Sprint(req.Attributes) != fmt.Sprint([]ldap.Attribute{{Type: "objectClass", Vals: []string{"group"}},
		{Type: "sAMAccountName", Vals: []string{"team"}}, {Type: "groupType", Vals: []string{"-2147483646"}}}) {
		t.Errorf("group: %v %v", err, req.Attributes)
	}
	_, err = d.create(context.Background(), "ad_computer", "computer", adIn{Parent: ou, Name: "pc1", writeIn: writeIn{Reason: "r"}}, "")
	got = map[string][]string{}
	for _, a := range (*sent)[2].(*ldap.AddRequest).Attributes {
		got[a.Type] = a.Vals
	}
	if err != nil || got["sAMAccountName"][0] != "pc1$" || got["userAccountControl"][0] != "4096" || len(got["unicodePwd"]) != 1 {
		t.Errorf("computer: %v %v", err, got)
	}

	for name, in := range map[string]adIn{
		"spn":       {Parent: ou, Name: "x", Attributes: map[string]string{"servicePrincipalName": "HTTP/x"}, writeIn: writeIn{Reason: "r"}},
		"no parent": {Name: "x", writeIn: writeIn{Reason: "r"}},
		"no reason": {Parent: ou, Name: "x"},
	} {
		if _, err := d.create(context.Background(), "ad_user", "user", in, ""); err == nil {
			t.Errorf("%s: created", name)
		}
	}
	if len(*sent) != 3 {
		t.Errorf("sent %d", len(*sent))
	}
}

// Delete is a plain leaf delete (never a tree delete) with confirm, and
// warns about sync; restore reanimates with show-deleted; a move warns
// about sync scope only when there is a counterpart.
func TestDeleteRestoreMove(t *testing.T) {
	d, _, sent := writeDeps(t, adaEntry(nil), "ad-delete", "ad-objects")
	ctx := context.Background()
	if _, err := d.deleteObject(ctx, adIn{ID: ada, writeIn: writeIn{Reason: "r", Confirm: "bob"}}); err == nil || len(*sent) != 0 {
		t.Errorf("confirm mismatch: %v", err)
	}
	out, err := d.deleteObject(ctx, adIn{ID: ada, writeIn: writeIn{Reason: "r", Confirm: "ada"}})
	if err != nil || !strings.Contains(fmt.Sprint(out["warning"]), "sync") {
		t.Fatalf("delete: %v %v", out, err)
	}
	if del, ok := (*sent)[0].(*ldap.DelRequest); !ok || del.DN != ada || len(del.Controls) != 0 {
		t.Errorf("delete sent %#v", (*sent)[0])
	}

	const gone = `CN=ada\0ADEL:6d2a1c3e-0000-4000-8000-000000000001,CN=Deleted Objects,DC=corp,DC=example,DC=com`
	d, _, sent = writeDeps(t, ldap.NewEntry(gone, map[string][]string{"objectClass": {"top", "user"}, "isDeleted": {"TRUE"},
		"lastKnownParent": {"CN=Users,DC=corp,DC=example,DC=com"}}), "ad-delete")
	out, err = d.restore(ctx, adIn{ID: gone, writeIn: writeIn{Reason: "r"}})
	if err != nil || out["restored_as"] != ada {
		t.Fatalf("restore: %v %v", out, err)
	}
	m := (*sent)[0].(*ldap.ModifyRequest)
	if fmt.Sprint(m.Changes) != fmt.Sprint([]ldap.Change{
		{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "isDeleted"}},
		{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "distinguishedName", Vals: []string{ada}}},
	}) || len(m.Controls) != 1 || m.Controls[0].GetControlType() != ldap.ControlTypeMicrosoftShowDeleted {
		t.Errorf("restore sent %v %v", m.Changes, m.Controls)
	}

	sidB, _ := ad.SIDBytes(testSID)
	for _, synced := range []bool{false, true} {
		d, _, sent := writeDeps(t, adaEntry(map[string][]string{"objectSid": {string(sidB)}}), "ad-objects")
		if synced {
			d.Graph, _ = graphStub(t, func(r *http.Request) string {
				if strings.HasSuffix(r.URL.Path, "/onPremisesSyncBehavior") {
					return `{"isCloudManaged":false}`
				}
				return `{"value":[{"id":"u1","onPremisesSyncEnabled":true}]}`
			})
		}
		out, err := d.moveOrRename(ctx, adIn{ActionParam: ActionParam{"move"}, ID: ada, Parent: "OU=Staff,DC=corp,DC=example,DC=com", writeIn: writeIn{Reason: "r"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, warned := out["warning"]; warned != synced {
			t.Errorf("synced=%v: %v", synced, out)
		}
		if r := (*sent)[0].(*ldap.ModifyDNRequest); r.NewRDN != "CN=ada" || r.NewSuperior != "OU=Staff,DC=corp,DC=example,DC=com" || !r.DeleteOldRDN {
			t.Errorf("move sent %+v", r)
		}
	}
	d, _, sent = writeDeps(t, adaEntry(nil), "ad-objects")
	if _, err := d.moveOrRename(ctx, adIn{ActionParam: ActionParam{"rename"}, ID: ada, Name: "Ada L", writeIn: writeIn{Reason: "r"}}); err != nil {
		t.Fatal(err)
	}
	if r := (*sent)[0].(*ldap.ModifyDNRequest); r.NewRDN != "CN=Ada L" || r.NewSuperior != "" {
		t.Errorf("rename sent %+v", r)
	}
	if out, _ := d.moveOrRename(ctx, adIn{ActionParam: ActionParam{"rename"}, ID: ada, Name: "Ada, L", writeIn: writeIn{Reason: "r"}}); out["dn"] != `CN=Ada\, L,CN=Users,DC=corp,DC=example,DC=com` {
		t.Errorf("rename reply %v", out)
	}
}

// With ad-objects and ad-delete on, the AD tools show create, and
// ad_object its writes with their parameters.
func TestObjectsAndDeleteRegister(t *testing.T) {
	cs := writeSession(t, "ad-objects", "ad-delete")
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"ad_user":     {"search", "get", "resultant_policy", "lockout", "create"},
		"ad_computer": {"search", "get", "create"},
		"ad_group":    {"search", "get", "members", "create"},
		"ad_object":   {"get", "search_deleted", "edit", "rename", "move", "delete", "restore"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: %v, want %v", name, got[name], want)
		}
	}
	for name, want := range map[string][]string{
		"ad_user":   {"reason", "parent", "name", "sam_account_name", "upn", "attributes"},
		"ad_group":  {"reason", "parent", "name", "group_scope", "distribution"},
		"ad_object": {"reason", "confirm", "parent", "name", "attributes"},
	} {
		p := props(t, cs, name)
		for _, w := range want {
			if !slices.Contains(p, w) {
				t.Errorf("%s lacks %s: %v", name, w, p)
			}
		}
		if slices.Contains(p, "must_change") || slices.Contains(p, "members") || name != "ad_object" && slices.Contains(p, "confirm") {
			t.Errorf("%s shows a parameter of a write it lacks: %v", name, p)
		}
	}
}

const staffOU = "OU=Staff,DC=corp,DC=example,DC=com"

func gpoDN(g string) string { return "CN={" + g + "},CN=Policies,CN=System,DC=corp,DC=example,DC=com" }

// link and unlink are a compare-and-swap of gPLink with the GPO's link
// added, changed or removed; block_inheritance sets gPOptions.
func TestGPOLinkWrites(t *testing.T) {
	a, b := gpoDN("AAAAAAAA-0000-4000-8000-000000000001"), gpoDN("BBBBBBBB-0000-4000-8000-000000000002")
	old := "[LDAP://" + strings.ToLower(a) + ";0]"
	d, buf, sent := writeDeps(t, ldap.NewEntry(staffOU, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "gPLink": {old}}), "ad-gpo-links")
	oldG := adGet
	adGet = func(_ *ad.Client, _ context.Context, id, class string, _ []string) (*ldap.Entry, error) {
		if class != adGPOs.class {
			t.Errorf("gpo read as %s", class)
		}
		return ldap.NewEntry(strings.ToUpper(id[:2])+id[2:], nil), nil
	}
	t.Cleanup(func() { adGet = oldG })
	ctx := context.Background()
	changes := func(i int) string { return fmt.Sprint((*sent)[i].(*ldap.ModifyRequest).Changes) }

	out, err := d.gpoLink(ctx, adIn{ActionParam: ActionParam{"link"}, ID: staffOU, GPO: b, Enforced: new(true), writeIn: writeIn{Reason: "r"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprint(swap("gPLink", old, "[LDAP://"+b+";2]"+old)); changes(0) != want {
		t.Errorf("link: %s, want %s", changes(0), want)
	}
	if l := out["links"].([]ad.Link); len(l) != 2 || l[1] != (ad.Link{GPO: b, LinkOrder: 2, Enforced: true}) {
		t.Errorf("links %+v", l)
	}
	if !strings.Contains(buf.String(), "capability=ad-gpo-links") || !strings.Contains(buf.String(), "attributes=[gPLink]") {
		t.Errorf("audit log:\n%s", buf)
	}
	// Changing the existing link in place: disabled, moved to 1 of 1.
	if _, err := d.gpoLink(ctx, adIn{ActionParam: ActionParam{"link"}, ID: staffOU, GPO: a, Enabled: new(false), LinkOrder: 1, writeIn: writeIn{Reason: "r"}}); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprint(swap("gPLink", old, "[LDAP://"+strings.ToLower(a)+";1]")); changes(1) != want {
		t.Errorf("relink: %s", changes(1))
	}
	if _, err := d.gpoLink(ctx, adIn{ActionParam: ActionParam{"unlink"}, ID: staffOU, GPO: a, writeIn: writeIn{Reason: "r"}}); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprint(swap("gPLink", old, "")); changes(2) != want {
		t.Errorf("unlink: %s", changes(2))
	}
	for _, in := range []adIn{
		{ActionParam: ActionParam{"unlink"}, ID: staffOU, GPO: b, writeIn: writeIn{Reason: "r"}},
		{ActionParam: ActionParam{"link"}, ID: staffOU, GPO: b, LinkOrder: 3, writeIn: writeIn{Reason: "r"}},
		{ActionParam: ActionParam{"link"}, ID: staffOU, writeIn: writeIn{Reason: "r"}},
	} {
		if _, err := d.gpoLink(ctx, in); err == nil {
			t.Errorf("%+v: sent", in)
		}
	}
	// The OU has no gPOptions: blocking adds 1; inheriting, already so, sends nothing.
	if _, err := d.blockInheritance(ctx, adIn{ID: staffOU, writeIn: writeIn{Reason: "r"}}); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprint(swap("gPOptions", "", "1")); changes(3) != want {
		t.Errorf("block: %s", changes(3))
	}
	if _, err := d.blockInheritance(ctx, adIn{ID: staffOU, Block: new(false), writeIn: writeIn{Reason: "r"}}); err == nil {
		t.Error("inherit sent")
	}
	// A deleted GPO's link is unlinked by DN.
	adGet = func(_ *ad.Client, _ context.Context, id, _ string, _ []string) (*ldap.Entry, error) {
		return nil, fmt.Errorf("%q: %w", id, ad.ErrNoMatch)
	}
	if _, err := d.gpoLink(ctx, adIn{ActionParam: ActionParam{"unlink"}, ID: staffOU, GPO: a, writeIn: writeIn{Reason: "r"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.gpoLink(ctx, adIn{ActionParam: ActionParam{"link"}, ID: staffOU, GPO: a, writeIn: writeIn{Reason: "r"}}); err == nil {
		t.Error("linked a missing GPO")
	}
	if len(*sent) != 5 {
		t.Errorf("sent %d", len(*sent))
	}
}

// A PSO write is refused while the PSO applies to a protected target, and
// apply refuses one; otherwise apply and unapply are one permissive modify.
func TestPSOWrites(t *testing.T) {
	const (
		pso  = "CN=weak," + "CN=Password Settings Container,CN=System,DC=corp,DC=example,DC=com"
		da   = "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"
		ops  = "CN=ops,CN=Users,DC=corp,DC=example,DC=com"
		team = "CN=team,CN=Users,DC=corp,DC=example,DC=com"
	)
	oldR := adReaches
	adReaches = func(_ *ad.Client, _ context.Context, dn string) (string, error) {
		return map[string]string{da: "a built-in account or group (RID 512)", ops: "its member CN=x is a protected target"}[dn], nil
	}
	t.Cleanup(func() { adReaches = oldR })
	notUniversal := func(d Deps) {
		adGet = func(_ *ad.Client, _ context.Context, id, class string, _ []string) (*ldap.Entry, error) {
			if class != psoTargets {
				t.Errorf("applies_to read as %s", class)
			}
			if strings.HasPrefix(id, "CN=universal,") {
				return nil, fmt.Errorf("%q: %w for this tool", id, ad.ErrNoMatch)
			}
			return ldap.NewEntry(id, nil), nil
		}
	}
	entry := func(appliesTo ...string) *ldap.Entry {
		return ldap.NewEntry(pso, map[string][]string{"objectClass": {"top", psoClass}, "msDS-PSOAppliesTo": appliesTo})
	}
	ctx := context.Background()
	in := func(action string, appliesTo ...string) adPolicyIn {
		return adPolicyIn{ActionParam: ActionParam{action}, ID: pso, AppliesTo: appliesTo, writeIn: writeIn{Reason: "r"},
			Attributes: map[string]string{"msDS-MinimumPasswordLength": "8"}}
	}
	for _, tc := range []struct {
		name  string
		entry *ldap.Entry
		in    adPolicyIn
		says  string
	}{
		{"apply to Domain Admins", entry(), in("apply", da), "applies_to " + da + ": protected target"},
		{"apply to a group reaching one", entry(team), in("apply", team, ops), "whatever capabilities are enabled: its member CN=x"},
		{"edit one applying to Domain Admins", entry(team, da), in("edit"), pso + " already applies to " + da + ": protected target"},
		{"unapply from one applying to Domain Admins", entry(da), in("unapply", da), "already applies to"},
		{"too many to check", ldap.NewEntry(pso, map[string][]string{"objectClass": {psoClass}, "msDS-PSOAppliesTo;range=0-1499": {team}}), in("edit"), "too many"},
		{"edit off the allowlist", entry(), adPolicyIn{ActionParam: ActionParam{"edit"}, ID: pso, writeIn: writeIn{Reason: "r"},
			Attributes: map[string]string{"description": "x"}}, "not a write this server makes"},
		{"apply nothing", entry(), in("apply"), "takes 1 to 20"},
		{"apply to a universal group", entry(), in("apply", "CN=universal,CN=Users,DC=corp,DC=example,DC=com"), "a user or global security group"},
		{"capability off", entry(), in("apply", team), "needs the ad-password-policy capability"},
	} {
		caps := []string{"ad-password-policy"}
		if tc.name == "capability off" {
			caps = nil
		}
		d, _, sent := writeDeps(t, tc.entry, caps...)
		notUniversal(d)
		if _, err := d.psoWrite(ctx, tc.in); err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if len(*sent) != 0 {
			t.Errorf("%s: sent %v", tc.name, (*sent)[0])
		}
	}

	d, buf, sent := writeDeps(t, entry(team), "ad-password-policy")
	out, err := d.psoWrite(ctx, in("apply", "CN=b,CN=Users,DC=corp,DC=example,DC=com", "CN=a,CN=Users,DC=corp,DC=example,DC=com", "CN=b,CN=Users,DC=corp,DC=example,DC=com"))
	if err != nil {
		t.Fatal(err)
	}
	m := (*sent)[0].(*ldap.ModifyRequest)
	if fmt.Sprint(m.Changes) != fmt.Sprint([]ldap.Change{{Operation: ldap.AddAttribute, Modification: ldap.PartialAttribute{Type: "msDS-PSOAppliesTo",
		Vals: []string{"CN=a,CN=Users,DC=corp,DC=example,DC=com", "CN=b,CN=Users,DC=corp,DC=example,DC=com"}}}}) ||
		ldap.FindControl(m.Controls, ldap.ControlTypeMicrosoftPermissiveModify) == nil || len(out["applies_to"].([]string)) != 2 {
		t.Errorf("apply: %v %v %v", m.Changes, m.Controls, out)
	}
	if !strings.Contains(buf.String(), "capability=ad-password-policy") {
		t.Errorf("audit log:\n%s", buf)
	}
	if _, err := d.psoWrite(ctx, in("unapply", team)); err != nil || (*sent)[1].(*ldap.ModifyRequest).Changes[0].Operation != ldap.DeleteAttribute {
		t.Errorf("unapply: %v", err)
	}
	if _, err := d.psoWrite(ctx, in("edit")); err != nil || fmt.Sprint((*sent)[2].(*ldap.ModifyRequest).Changes) != fmt.Sprint([]ldap.Change{
		{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "msDS-MinimumPasswordLength", Vals: []string{"8"}}}}) {
		t.Errorf("edit: %v", err)
	}
}

// create of a PSO needs every setting, and nothing else, under ad-password-policy.
func TestCreatePSO(t *testing.T) {
	d, buf, sent := writeDeps(t, adaEntry(nil), "ad-password-policy")
	const psc = "CN=Password Settings Container,CN=System,DC=corp,DC=example,DC=com"
	settings := map[string]string{}
	for _, a := range psoSettings {
		settings[a] = "1"
	}
	out, err := d.create(context.Background(), "ad_policy", psoClass, adIn{Parent: psc, Name: "strict", Attributes: settings, writeIn: writeIn{Reason: "r"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	req := (*sent)[0].(*ldap.AddRequest)
	if out["dn"] != "CN=strict,"+psc || out["sAMAccountName"] != nil || req.Attributes[0].Vals[0] != psoClass || len(req.Attributes) != 1+len(psoSettings) {
		t.Errorf("create: %v %v", out, req.Attributes)
	}
	if !strings.Contains(buf.String(), "capability=ad-password-policy") {
		t.Errorf("audit log:\n%s", buf)
	}
	settings["msds-lockoutthreshold"] = settings["msDS-LockoutThreshold"]
	delete(settings, "msDS-LockoutThreshold")
	if _, err := d.create(context.Background(), "ad_policy", psoClass, adIn{Parent: psc, Name: "y", Attributes: settings, writeIn: writeIn{Reason: "r"}}, ""); err != nil {
		t.Errorf("a setting in another case: %v", err)
	}
	delete(settings, "msDS-LockoutDuration")
	if _, err := d.create(context.Background(), "ad_policy", psoClass, adIn{Parent: psc, Name: "x", Attributes: settings, writeIn: writeIn{Reason: "r"}}, ""); err == nil ||
		!strings.Contains(err.Error(), "missing msDS-LockoutDuration") {
		t.Errorf("missing: %v", err)
	}
	settings["msDS-LockoutDuration"], settings["description"] = "1", "x"
	if _, err := d.create(context.Background(), "ad_policy", psoClass, adIn{Parent: psc, Name: "x", Attributes: settings, writeIn: writeIn{Reason: "r"}}, ""); err == nil {
		t.Error("created with description")
	}
	if len(*sent) != 2 {
		t.Errorf("sent %d", len(*sent))
	}
}

func TestPolicyWritesRegister(t *testing.T) {
	cs := writeSession(t, "ad-gpo-links", "ad-password-policy")
	got := listed(t, cs)
	for name, want := range map[string][]string{
		"ad_gpo":    {"search", "get", "links", "link", "unlink", "block_inheritance"},
		"ad_policy": {"domain_default", "psos", "create", "edit", "apply", "unapply"},
		"ad_ou":     {"search", "get", "tree"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: %v, want %v", name, got[name], want)
		}
	}
	for name, want := range map[string][]string{
		"ad_gpo":    {"reason", "gpo", "link_order", "enforced", "enabled", "block"},
		"ad_policy": {"reason", "name", "attributes", "applies_to"},
	} {
		p := props(t, cs, name)
		for _, w := range want {
			if !slices.Contains(p, w) {
				t.Errorf("%s lacks %s: %v", name, w, p)
			}
		}
		if slices.Contains(p, "parent") || slices.Contains(p, "confirm") || name == "ad_gpo" && slices.Contains(p, "attributes") {
			t.Errorf("%s shows a parameter of a write it lacks: %v", name, p)
		}
	}
}
