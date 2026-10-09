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

	tgt, err := c.Modify(ctx, plain, userClass, nil, describe)
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
		_, err := c.Modify(ctx, dn, "(objectClass=*)", nil, describe)
		if !errors.Is(err, ErrProtected) {
			t.Errorf("%s: want a protected refusal, got %v", name, err)
		}
	}
	if len(f.modifies) != 1 {
		t.Errorf("a protected target was written: %q", f.modifies)
	}
	// A group in no group has no tokenGroups, and that is no refusal.
	if _, err := c.Modify(ctx, lonely, "(objectClass=group)", nil, describe); err != nil || len(f.modifies) != 2 {
		t.Errorf("lonely: %v %q", err, f.modifies)
	}

	// vet refusing sends nothing; a wrong class matches nothing.
	boom := errors.New("confirm mismatch")
	if _, err := c.Modify(ctx, plain, userClass, nil, func(*ldap.Entry) (any, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("vet error: %v", err)
	}
	if _, err := c.Modify(ctx, plain, "(objectClass=computer)", nil, describe); !errors.Is(err, ErrNoMatch) {
		t.Errorf("wrong class: %v", err)
	}
	if len(f.modifies) != 2 {
		t.Errorf("sent anyway: %q", f.modifies)
	}

	// insufficientAccessRights comes back as itself, with a delegation hint.
	f.denied = map[string]bool{strings.ToLower(plain): true}
	_, err = c.Modify(ctx, plain, userClass, nil, describe)
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
	if _, err := c.Modify(ctx, plain, userClass, nil, cas("512", "514")); err != nil {
		t.Fatal(err)
	}
	if got := f.tree[strings.ToLower(plain)]["userAccountControl"]; !slices.Equal(got, []string{"514"}) {
		t.Errorf("after: %v", got)
	}
	if _, err := c.Modify(ctx, plain, userClass, nil, cas("512", "514")); !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
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
