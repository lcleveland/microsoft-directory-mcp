package ad

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const userClass = "(&(objectCategory=person)(objectClass=user))"

var (
	jdoeCorp  = "CN=jdoe,CN=Users," + corpDN
	jdoeChild = "CN=jdoe,CN=Users," + childDN
	solo      = "CN=solo,CN=Users," + childDN
)

// seedUsers adds jdoe to both domains, solo to the child only, and a group.
func seedUsers(f *fakeDir) {
	user := func(dn, sam string, extra map[string][]string) {
		attrs := map[string][]string{"objectClass": {"top", "person", "user"}, "objectCategory": {"person"},
			"sAMAccountName": {sam}, "userAccountControl": {"512"}}
		for k, v := range extra {
			attrs[k] = v
		}
		f.tree[strings.ToLower(dn)] = attrs
	}
	user(jdoeCorp, "jdoe", nil)
	user(jdoeChild, "jdoe", nil)
	user(solo, "solo", map[string][]string{"objectSid": {sidBytes}, "objectGUID": {guidBytes},
		"userPrincipalName": {"solo@child.corp.example.com"}})
	f.tree[strings.ToLower("CN=grp,CN=Users,"+corpDN)] = map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"grp"}}
}

func TestResolve(t *testing.T) {
	f := newFakeDir()
	seedUsers(f)
	c := f.client(srvConfig())
	ctx := context.Background()
	for id, want := range map[string]string{
		solo:                                     solo,
		"S-1-5-21-1-2-3-1104":                    solo,
		"00112233-4455-6677-8899-aabbccddeeff":   solo,
		"{00112233-4455-6677-8899-AABBCCDDEEFF}": solo,
		"solo@child.corp.example.com":            solo,
		"solo":                                   solo,
		`CHILD\jdoe`:                             jdoeChild,
		`corp.example.com\jdoe`:                  jdoeCorp,
	} {
		if got, err := c.Resolve(ctx, id, userClass); err != nil || !strings.EqualFold(got, want) {
			t.Errorf("%s: want %s, got %q %v", id, want, got, err)
		}
	}
	// A sAMAccountName in two domains names each DN.
	_, err := c.Resolve(ctx, "jdoe", userClass)
	if err == nil || !strings.Contains(err.Error(), strings.ToLower(jdoeCorp)) || !strings.Contains(err.Error(), strings.ToLower(jdoeChild)) {
		t.Errorf("ambiguous: %v", err)
	}
	for _, id := range []string{"nobody", "grp", "S-1-5-21-9-9-9-9", "nobody@corp.example.com"} {
		if _, err := c.Resolve(ctx, id, userClass); err == nil || !strings.Contains(err.Error(), "no match") {
			t.Errorf("%s: want no match, got %v", id, err)
		}
	}
	// SID, GUID and UPN go to the GC; nothing else does.
	for _, s := range f.searches {
		if strings.HasPrefix(s, "dc1.corp.example.com:3269 ") && strings.Contains(s, "sAMAccountName") {
			t.Errorf("sAMAccountName searched on the GC: %s", s)
		}
	}
}

func TestGetReadsFromOwningDomain(t *testing.T) {
	f := newFakeDir()
	seedUsers(f)
	c := f.client(srvConfig())
	e, err := c.Get(context.Background(), "S-1-5-21-1-2-3-1104", userClass, []string{"sAMAccountName"})
	if err != nil || e.GetAttributeValue("sAMAccountName") != "solo" {
		t.Fatalf("get: %+v %v", e, err)
	}
	last := f.searches[len(f.searches)-1]
	if want := fmt.Sprintf(".child.corp.example.com:636 %s", solo); !strings.Contains(strings.ToLower(last), strings.ToLower(want)) {
		t.Errorf("read went to %s", last)
	}
	if _, err := c.Get(context.Background(), "CN=grp,CN=Users,"+corpDN, userClass, nil); err == nil || !strings.Contains(err.Error(), "no match") {
		t.Errorf("group as user: %v", err)
	}
}

// seedMany adds n users to each domain, each with a description of pad bytes.
func seedMany(f *fakeDir, n, pad int) int {
	for _, d := range []string{corpDN, childDN} {
		for i := range n {
			f.tree[strings.ToLower(fmt.Sprintf("CN=u%03d,OU=Bulk,%s", i, d))] = map[string][]string{
				"objectClass": {"user"}, "objectCategory": {"person"}, "sAMAccountName": {fmt.Sprintf("u%03d", i)},
				"description": {strings.Repeat("x", pad)}}
		}
	}
	return 2 * n
}

// all pages through q and returns every result, failing on any page over the caps.
func all(t *testing.T, c *Client, q Query) []map[string]any {
	t.Helper()
	var out []map[string]any
	cur := ""
	for range 50 {
		p, err := c.Search(context.Background(), q, cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Results) > 200 {
			t.Fatalf("page of %d", len(p.Results))
		}
		if b, _ := json.Marshal(p.Results); len(b) > 60<<10 {
			t.Fatalf("page of %d bytes", len(b))
		}
		out = append(out, p.Results...)
		if cur = p.NextCursor; cur == "" {
			return out
		}
	}
	t.Fatal("cursor never ended")
	return nil
}

func TestSearchPagesAcrossDomains(t *testing.T) {
	f := newFakeDir()
	want := seedMany(f, 150, 0)
	c := f.client(srvConfig())
	q := Query{Filter: userClass, Attrs: []string{"sAMAccountName"}}
	p, err := c.Search(context.Background(), q, "")
	if err != nil || len(p.Results) != 200 || p.NextCursor == "" || p.Truncation != nil {
		t.Fatalf("first page: %d results, cursor %q, %v", len(p.Results), p.NextCursor, err)
	}
	got := all(t, c, q)
	seen := map[string]bool{}
	for _, r := range got {
		seen[r["dn"].(string)] = true
	}
	if len(got) != want || len(seen) != want {
		t.Errorf("want %d distinct, got %d (%d distinct)", want, len(got), len(seen))
	}
	// Narrowed to one domain.
	if got := all(t, c, Query{Domain: "CHILD", Filter: userClass, Attrs: []string{"sAMAccountName"}}); len(got) != want/2 {
		t.Errorf("child only: %d", len(got))
	}
}

func TestSearchByteCapKeepsTheRest(t *testing.T) {
	f := newFakeDir()
	want := seedMany(f, 100, 1024)
	c := f.client(srvConfig())
	q := Query{Filter: userClass, Attrs: []string{"description"}}
	p, err := c.Search(context.Background(), q, "")
	if err != nil || p.Truncation == nil || p.Truncation.Returned != len(p.Results) || p.Truncation.Of != 200 || p.NextCursor == "" {
		t.Fatalf("first page: %d results, truncation %+v, %v", len(p.Results), p.Truncation, err)
	}
	if got := all(t, c, q); len(got) != want {
		t.Errorf("trimmed entries lost: %d of %d", len(got), want)
	}
}

func TestCursorExpiry(t *testing.T) {
	f := newFakeDir()
	seedMany(f, 150, 0)
	c := f.client(srvConfig())
	now := time.Now()
	c.now = func() time.Time { return now }
	q := Query{Filter: userClass}
	p, err := c.Search(context.Background(), q, "")
	if err != nil || p.NextCursor == "" {
		t.Fatal(p, err)
	}
	if _, err := c.Search(context.Background(), Query{Filter: "(objectClass=group)"}, p.NextCursor); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("other query: %v", err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := c.Search(context.Background(), q, p.NextCursor); err == nil || !strings.Contains(err.Error(), "cursor expired, re-run the search") {
		t.Errorf("idle: %v", err)
	}
	// A broken pinned connection expires it too, as does a restart (an unknown id).
	p, _ = c.Search(context.Background(), q, "")
	f.kill("dc1.corp.example.com", "dc2.corp.example.com")
	if _, err := c.Search(context.Background(), q, p.NextCursor); err == nil || !strings.Contains(err.Error(), "cursor expired") {
		t.Errorf("reconnect: %v", err)
	}
	if _, err := f.client(srvConfig()).Search(context.Background(), q, p.NextCursor); err == nil || !strings.Contains(err.Error(), "cursor expired") {
		t.Errorf("restart: %v", err)
	}
}

func TestMembersByRange(t *testing.T) {
	f := newFakeDir()
	seedMany(f, 300, 0)
	grp := "CN=big,CN=Users," + corpDN
	var members []string
	for _, d := range []string{corpDN, childDN} {
		for i := range 225 {
			members = append(members, fmt.Sprintf("CN=u%03d,OU=Bulk,%s", i, d))
		}
	}
	members = append(members, "CN=gone,"+corpDN)
	f.tree[strings.ToLower(grp)] = map[string][]string{"objectClass": {"group"}, "member": members}
	c := f.client(srvConfig())
	ctx := context.Background()

	var got []string
	for off, pages := 0, 0; off >= 0; pages++ {
		vals, next, err := c.Values(ctx, grp, "member", off, 200)
		if err != nil || pages > 3 || next >= 0 && len(vals) != 200 {
			t.Fatalf("offset %d: %d values, next %d, %v", off, len(vals), next, err)
		}
		got, off = append(got, vals...), next
	}
	if len(got) != len(members) {
		t.Fatalf("%d of %d members", len(got), len(members))
	}

	ents, err := c.ReadMany(ctx, got[:300], []string{"sAMAccountName"})
	if err != nil || len(ents) != 300 {
		t.Fatalf("ReadMany: %d %v", len(ents), err)
	}
	if ents[0]["sAMAccountName"] != "u000" || !strings.EqualFold(ents[299]["dn"].(string), got[299]) {
		t.Errorf("order: %v %v", ents[0], ents[299])
	}
	// A member that can't be read still shows its DN.
	ents, _ = c.ReadMany(ctx, got[len(got)-1:], nil)
	if len(ents) != 1 || len(ents[0]) != 1 || ents[0]["dn"] != "CN=gone,"+corpDN {
		t.Errorf("missing member: %v", ents)
	}
}
