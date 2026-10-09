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
func writeDeps(t *testing.T, e *ldap.Entry, caps ...string) (Deps, *bytes.Buffer, *[]*ldap.ModifyRequest) {
	t.Helper()
	a, err := ad.New(&config.AD{TLS: "ldaps", DCs: []string{"127.0.0.1:1"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var sent []*ldap.ModifyRequest
	old := adModify
	adModify = func(_ *ad.Client, _ context.Context, dn, _ string, _ []string, vet func(*ldap.Entry) (*ldap.ModifyRequest, error)) (ad.Target, error) {
		if !strings.EqualFold(dn, e.DN) {
			t.Errorf("wrote %s, want %s", dn, e.DN)
		}
		req, err := vet(e)
		if err == nil {
			sent = append(sent, req)
		}
		return ad.Target{DC: "dc2.corp.example.com:636"}, err
	}
	oldP := adProtected
	adProtected = func(*ad.Client, context.Context, string) (string, error) { return "", nil }
	t.Cleanup(func() { adModify, adProtected = old, oldP })
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
	got := fmt.Sprint((*sent)[0].Changes)
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
		if got := (*sent)[0].Changes; fmt.Sprint(got) != fmt.Sprint(want) {
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
		req := (*sent)[0]
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
