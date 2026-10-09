package ad

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func sid(s string) string {
	b, err := SIDBytes(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

const (
	corpSID  = "S-1-5-21-1-2-3"
	childSID = "S-1-5-21-4-5-6"
	plain    = "CN=plain,CN=Users," + corpDN
	lonely   = "CN=lonely,CN=Users," + corpDN
)

// seedProtected adds a user for every protected-target rule, plus plain,
// which none of them catches, and lonely, a group in no group. tokenGroups
// is what the DC would compute.
func seedProtected(f *fakeDir) map[string]string {
	user := func(dn, rid string, tokens []string, extra map[string][]string) {
		attrs := map[string][]string{"objectClass": {"top", "person", "user"}, "objectCategory": {"person"},
			"sAMAccountName": {strings.TrimPrefix(strings.Split(dn, ",")[0], "CN=")}, "userAccountControl": {"512"},
			"primaryGroupID": {"513"}, "objectSid": {sid(rid)}}
		for _, t := range tokens {
			attrs["tokenGroups"] = append(attrs["tokenGroups"], sid(t))
		}
		for k, v := range extra {
			attrs[k] = v
		}
		f.tree[strings.ToLower(dn)] = attrs
	}
	users := []string{corpSID + "-513"}
	user(plain, corpSID+"-1104", users, nil)
	f.tree[strings.ToLower(lonely)] = map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"lonely"},
		"objectSid": {sid(corpSID + "-1300")}}
	cases := map[string]string{
		"adminCount":             "CN=admincount,CN=Users," + corpDN,
		"built-in":               "CN=Administrator,CN=Users," + corpDN,
		"isCriticalSystemObject": "CN=critical,CN=Users," + corpDN,
		"domain controller":      "CN=DC9,OU=Domain Controllers," + corpDN,
		"primary group":          "CN=primary,CN=Users," + corpDN,
		"nested":                 "CN=nested,CN=Users," + corpDN,
		"in builtin":             "CN=operator,CN=Users," + corpDN,
		"child in root":          "CN=childops,CN=Users," + childDN,
		"tokenGroups unreadable": "CN=hidden,CN=Users," + corpDN,
		"Domain Controllers OU":  "OU=Domain Controllers," + corpDN,
	}
	f.tree[strings.ToLower(cases["Domain Controllers OU"])] = map[string][]string{"objectClass": {"top", "organizationalUnit"}}
	user(cases["adminCount"], corpSID+"-1105", users, map[string][]string{"adminCount": {"1"}})
	user(cases["built-in"], corpSID+"-500", users, nil)
	user(cases["isCriticalSystemObject"], corpSID+"-1106", users, map[string][]string{"isCriticalSystemObject": {"TRUE"}})
	user(cases["domain controller"], corpSID+"-1107", users, map[string][]string{"userAccountControl": {"532480"}})
	user(cases["primary group"], corpSID+"-1108", []string{corpSID + "-512"}, map[string][]string{"primaryGroupID": {"512"}})
	user(cases["nested"], corpSID+"-1109", append(users, corpSID+"-1200", corpSID+"-512"), nil)
	user(cases["in builtin"], corpSID+"-1110", append(users, "S-1-5-32-544"), nil)
	user(cases["child in root"], childSID+"-1111", []string{childSID + "-513", childSID + "-1200", corpSID + "-519"}, nil)
	user(cases["tokenGroups unreadable"], corpSID+"-1112", nil, nil)
	return cases
}

func describe(e *ldap.Entry) (any, error) {
	req := ldap.NewModifyRequest(e.DN, nil)
	req.Replace("description", []string{"x"})
	return req, nil
}

// A write reads its target on the PDC emulator, refuses every kind of
// protected target there, and otherwise sends vet's modify once.
func TestModifyRails(t *testing.T) {
	f := newFakeDir()
	cases := seedProtected(f)
	c := f.client(srvConfig())
	ctx := context.Background()

	tgt, err := c.Modify(ctx, plain, userClass, nil, describe, nil)
	if err != nil || tgt != (Target{DC: "dc2.corp.example.com:636"}) {
		t.Fatalf("plain: %+v %v", tgt, err)
	}
	if !slices.Equal(f.modifies, []string{"dc2.corp.example.com " + strings.ToLower(plain)}) || f.tree[strings.ToLower(plain)]["description"][0] != "x" {
		t.Errorf("modifies %q", f.modifies)
	}
	if !slices.ContainsFunc(f.searches, func(s string) bool { return strings.HasPrefix(s, "dc2.corp.example.com:636 "+plain+" ") }) {
		t.Errorf("no pre-read on the PDC: %q", f.searches)
	}

	for name, dn := range cases {
		_, err := c.Modify(ctx, dn, "(objectClass=*)", nil, describe, nil)
		if !errors.Is(err, ErrProtected) {
			t.Errorf("%s: want a protected refusal, got %v", name, err)
		}
	}
	if len(f.modifies) != 1 {
		t.Errorf("a protected target was written: %q", f.modifies)
	}
	// A group in no group has no tokenGroups, and that is no refusal.
	if _, err := c.Modify(ctx, lonely, "(objectClass=group)", nil, describe, nil); err != nil || len(f.modifies) != 2 {
		t.Errorf("lonely: %v %q", err, f.modifies)
	}

	// A domain head (isCriticalSystemObject) takes a gPLink or gPOptions modify alone.
	head := f.tree[strings.ToLower(corpDN)]
	head["objectClass"], head["isCriticalSystemObject"] = []string{"top", "domain", "domainDNS"}, []string{"TRUE"}
	gpo := func(attrs ...string) func(*ldap.Entry) (any, error) {
		return func(e *ldap.Entry) (any, error) {
			req := ldap.NewModifyRequest(e.DN, nil)
			for _, a := range attrs {
				req.Replace(a, []string{"1"})
			}
			return req, nil
		}
	}
	if _, err := c.Modify(ctx, corpDN, "(objectClass=domainDNS)", nil, gpo("gPLink", "gPOptions"), nil); err != nil || len(f.modifies) != 3 {
		t.Errorf("domain head gPLink: %v %q", err, f.modifies)
	}
	for _, vet := range []func(*ldap.Entry) (any, error){describe, gpo("gPOptions", "description"), gpo(),
		func(e *ldap.Entry) (any, error) { return ldap.NewDelRequest(e.DN, nil), nil }} {
		if _, err := c.Modify(ctx, corpDN, "(objectClass=*)", nil, vet, nil); !errors.Is(err, ErrProtected) {
			t.Errorf("domain head: want a protected refusal, got %v", err)
		}
	}
	if _, err := c.Modify(ctx, "OU=Domain Controllers,"+corpDN, "(objectClass=*)", nil, gpo("gPLink"), nil); !errors.Is(err, ErrProtected) {
		t.Errorf("Domain Controllers OU gPLink: %v", err)
	}
	if len(f.modifies) != 3 {
		t.Errorf("sent anyway: %q", f.modifies)
	}

	// vet refusing sends nothing; a wrong class matches nothing.
	boom := errors.New("confirm mismatch")
	if _, err := c.Modify(ctx, plain, userClass, nil, func(*ldap.Entry) (any, error) { return nil, boom }, nil); !errors.Is(err, boom) {
		t.Errorf("vet error: %v", err)
	}
	if _, err := c.Modify(ctx, plain, "(objectClass=computer)", nil, describe, nil); !errors.Is(err, ErrNoMatch) {
		t.Errorf("wrong class: %v", err)
	}
	if len(f.modifies) != 3 {
		t.Errorf("sent anyway: %q", f.modifies)
	}

	// insufficientAccessRights comes back as itself, with a delegation hint.
	f.denied = map[string]bool{strings.ToLower(plain): true}
	_, err = c.Modify(ctx, plain, userClass, nil, describe, nil)
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) || !strings.Contains(err.Error(), "write access to description") {
		t.Errorf("denied: %v", err)
	}
}

// Disabling is a compare-and-swap on the userAccountControl value read.
func TestModifyCompareAndSwap(t *testing.T) {
	f := newFakeDir()
	seedProtected(f)
	c := f.client(srvConfig())
	cas := func(old, new string) func(*ldap.Entry) (any, error) {
		return func(e *ldap.Entry) (any, error) {
			req := ldap.NewModifyRequest(e.DN, nil)
			req.Delete("userAccountControl", []string{old})
			req.Add("userAccountControl", []string{new})
			return req, nil
		}
	}
	ctx := context.Background()
	if _, err := c.Modify(ctx, plain, userClass, nil, cas("512", "514"), nil); err != nil {
		t.Fatal(err)
	}
	if got := f.tree[strings.ToLower(plain)]["userAccountControl"]; !slices.Equal(got, []string{"514"}) {
		t.Errorf("after: %v", got)
	}
	if _, err := c.Modify(ctx, plain, userClass, nil, cas("512", "514"), nil); !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
		t.Errorf("stale value: %v", err)
	}
}

// Protected reads any object, from any DC of its domain, as Modify's
// pre-read does: why it is protected, or "".
func TestProtected(t *testing.T) {
	f := newFakeDir()
	cases := seedProtected(f)
	c := f.client(srvConfig())
	for name, dn := range cases {
		if why, err := c.Protected(context.Background(), dn); err != nil || why == "" {
			t.Errorf("%s: %q %v", name, why, err)
		}
	}
	for _, dn := range []string{plain, lonely} {
		if why, err := c.Protected(context.Background(), dn); err != nil || why != "" {
			t.Errorf("%s: %q %v", dn, why, err)
		}
	}
	if _, err := c.Protected(context.Background(), "CN=gone,CN=Users,"+corpDN); !errors.Is(err, ErrNoMatch) {
		t.Errorf("missing: %v", err)
	}
	if len(f.modifies) != 0 {
		t.Errorf("wrote: %q", f.modifies)
	}
}

// Reaches refuses a protected user or group, and a group with a protected
// member, direct or nested, or one only just put in a protected group.
func TestReaches(t *testing.T) {
	f := newFakeDir()
	cases := seedProtected(f)
	c := f.client(srvConfig())
	f.tree[strings.ToLower(corpDN)]["objectSid"] = []string{sid(corpSID)}
	da := "CN=Domain Admins,CN=Users," + corpDN
	f.tree[strings.ToLower(da)] = map[string][]string{"objectClass": {"top", "group"}, "objectSid": {sid(corpSID + "-512")},
		"isCriticalSystemObject": {"TRUE"}}
	group := func(name, rid string, memberOf ...string) string {
		dn := "CN=" + name + ",CN=Users," + corpDN
		attrs := map[string][]string{"objectClass": {"top", "group"}, "objectSid": {sid(corpSID + "-" + rid)}, "memberOf": memberOf}
		for _, g := range memberOf {
			attrs["tokenGroups"] = append(attrs["tokenGroups"], f.tree[strings.ToLower(g)]["objectSid"]...)
		}
		f.tree[strings.ToLower(dn)] = attrs
		return dn
	}
	member := func(dn string, groups ...string) {
		f.tree[strings.ToLower(dn)]["memberOf"] = append(f.tree[strings.ToLower(dn)]["memberOf"], groups...)
	}
	team := group("team", "1301")
	member(plain, team)
	outer := group("outer", "1302")
	ops := group("ops", "1303", outer)
	// fresh joined Domain Admins after SDProp last ran: no adminCount yet, and its tokenGroups aren't read.
	fresh := "CN=fresh,CN=Users," + corpDN
	f.tree[strings.ToLower(fresh)] = map[string][]string{"objectClass": {"top", "user"}, "objectSid": {sid(corpSID + "-1304")}}
	member(fresh, ops, da)
	withAdmin := group("withadmin", "1305")
	member(cases["adminCount"], withAdmin)
	withDA := group("withda", "1306")
	member(da, withDA)

	for dn, want := range map[string]string{
		plain: "", team: "", lonely: "",
		cases["adminCount"]: "adminCount=1", da: "isCriticalSystemObject", cases["nested"]: "protected group",
		ops: "its member " + fresh, outer: "its member " + fresh, withAdmin: "its member " + cases["adminCount"],
		withDA: "its member " + da,
	} {
		why, err := c.Reaches(context.Background(), dn)
		if err != nil || want == "" && why != "" || want != "" && !strings.Contains(strings.ToLower(why), strings.ToLower(want)) {
			t.Errorf("%s: %q %v, want %q", dn, why, err, want)
		}
	}
	if len(f.modifies) != 0 {
		t.Errorf("wrote: %q", f.modifies)
	}
}

// The protected groups tokenGroups can't show or that have no fixed RID:
// the root domain's BUILTIN groups for a principal of another domain,
// DnsAdmins and --protected-groups, nested; and an unreadable cross-domain
// membership refuses the write.
func TestGuard(t *testing.T) {
	f := newFakeDir()
	cfg := srvConfig()
	cfg.ProtectedGroups = []string{`CORP\guarded`}
	c := f.client(cfg)
	add := func(dn, s string, attrs map[string][]string) string {
		attrs["objectSid"] = []string{sid(s)}
		attrs["sAMAccountName"] = []string{strings.TrimPrefix(strings.Split(dn, ",")[0], "CN=")}
		f.tree[strings.ToLower(dn)] = attrs
		return dn
	}
	group := func(attrs map[string][]string) map[string][]string {
		attrs["objectClass"] = []string{"top", "group"}
		return attrs
	}
	user := func(dn, s string, tokens ...string) string {
		attrs := map[string][]string{"objectClass": {"top", "user"}, "primaryGroupID": {"513"}}
		for _, t := range tokens {
			attrs["tokenGroups"] = append(attrs["tokenGroups"], sid(t))
		}
		return add(dn, s, attrs)
	}
	admins := "CN=Administrators,CN=Builtin," + corpDN
	helpdesk := "CN=helpdesk,CN=Users," + childDN // a child global group in a root domain-local group in root Administrators
	direct := user("CN=direct,CN=Users,"+childDN, childSID+"-1401", childSID+"-513")
	nested := user("CN=nested,CN=Users,"+childDN, childSID+"-1402", childSID+"-513", childSID+"-1400")
	free := user("CN=free,CN=Users,"+childDN, childSID+"-1403", childSID+"-513")
	add(helpdesk, childSID+"-1400", group(map[string][]string{}))
	add(admins, "S-1-5-32-544", group(map[string][]string{"isCriticalSystemObject": {"TRUE"}, "member": {direct, "CN=rootlocal,CN=Users," + corpDN}}))
	add("CN=rootlocal,CN=Users,"+corpDN, corpSID+"-1400", group(map[string][]string{"member": {helpdesk}, "memberOf": {admins}}))
	add("CN=DnsAdmins,CN=Users,"+corpDN, corpSID+"-1101", group(map[string][]string{}))
	dnsAdmin := user("CN=dnsadmin,CN=Users,"+corpDN, corpSID+"-1410", corpSID+"-513", corpSID+"-1101")
	add("CN=guarded,CN=Users,"+corpDN, corpSID+"-1102", group(map[string][]string{}))
	add("CN=inner,CN=Users,"+corpDN, corpSID+"-1103", group(map[string][]string{"memberOf": {"CN=guarded,CN=Users," + corpDN}}))
	guarded := user("CN=guardee,CN=Users,"+corpDN, corpSID+"-1411", corpSID+"-513", corpSID+"-1103", corpSID+"-1102")
	ctx := context.Background()

	for dn, want := range map[string]string{
		direct: "protected group of corp.example.com", nested: "through cn=rootlocal", dnsAdmin: "cn=dnsadmins",
		guarded: "cn=guarded", free: "",
	} {
		why, err := c.Protected(ctx, dn)
		if err != nil || want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%s: %q %v, want %q", dn, why, err, want)
		}
		if _, err := c.Modify(ctx, dn, "(objectClass=*)", nil, describe); want != "" && !errors.Is(err, ErrProtected) || want == "" && err != nil {
			t.Errorf("modify %s: %v", dn, err)
		}
	}
	if len(f.modifies) != 1 {
		t.Errorf("modifies %q", f.modifies)
	}

	// No GC, so free's groups can't be found in the root domain: refused, not written.
	f.dead["dc1.corp.example.com"] = true
	c = f.client(cfg)
	if why, err := c.Protected(ctx, free); err == nil || !strings.Contains(err.Error(), "global catalog") {
		t.Errorf("no GC: %q", why)
	}
	if _, err := c.Modify(ctx, free, "(objectClass=*)", nil, describe); err == nil || len(f.modifies) != 1 {
		t.Errorf("no GC modify: %v %q", err, f.modifies)
	}
	// An unresolvable --protected-groups group refuses too.
	delete(f.dead, "dc1.corp.example.com")
	cfg.ProtectedGroups = []string{`CORP\gone`}
	if why, err := f.client(cfg).Protected(ctx, free); err == nil || !strings.Contains(err.Error(), "--protected-groups") {
		t.Errorf("gone: %q %v", why, err)
	}
}
