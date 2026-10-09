package ad

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	gpoA = "cn={AAAAAAAA-0000-0000-0000-000000000000},cn=policies,cn=system," + corpDN
	gpoB = "cn={BBBBBBBB-0000-0000-0000-000000000000},cn=policies,cn=system," + corpDN
	gpoC = "cn={CCCCCCCC-0000-0000-0000-000000000000},cn=policies,cn=system," + corpDN
	gpoD = "cn={DDDDDDDD-0000-0000-0000-000000000000},cn=policies,cn=system," + corpDN
)

func TestParseGPLink(t *testing.T) {
	// The string lists links last-first: its final entry is link order 1.
	got := ParseGPLink("[LDAP://" + gpoA + ";0][ldap://" + gpoB + ";2][LDAP://" + gpoC + ";1][LDAP://" + gpoD + ";3]")
	want := []Link{
		{GPO: gpoD, LinkOrder: 1, Enforced: true, Disabled: true},
		{GPO: gpoC, LinkOrder: 2, Disabled: true},
		{GPO: gpoB, LinkOrder: 3, Enforced: true},
		{GPO: gpoA, LinkOrder: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	for _, empty := range []string{"", " ", "[]"} {
		if got := ParseGPLink(empty); len(got) != 0 {
			t.Errorf("%q: %+v", empty, got)
		}
	}
}

func TestInheritance(t *testing.T) {
	dom, ou, child := SOM{DN: corpDN}, SOM{DN: "OU=a," + corpDN}, SOM{DN: "OU=b,OU=a," + corpDN}
	dom.Links = ParseGPLink("[LDAP://" + gpoD + ";0][LDAP://" + gpoA + ";2]") // A enforced, order 1; D order 2
	ou.Links = ParseGPLink("[LDAP://" + gpoB + ";0][LDAP://" + gpoC + ";1]")  // C disabled
	child.Links = ParseGPLink("[LDAP://" + gpoC + ";2][LDAP://" + gpoB + ";0]")
	names := func(as []Applied) (out []string) {
		for _, a := range as {
			out = append(out, a.GPO[4:5]+"@"+strings.SplitN(a.From, ",", 2)[0])
		}
		return out
	}
	// Enforced links first, highest container first; then the rest, nearest
	// container first, each in link order; disabled links never apply.
	got := Inheritance([]SOM{dom, ou, child})
	if want := []string{"A@DC=corp", "C@OU=b", "B@OU=b", "B@OU=a", "D@DC=corp"}; !reflect.DeepEqual(names(got), want) {
		t.Errorf("no block: %v, want %v", names(got), want)
	}
	for i, a := range got {
		if a.Precedence != i+1 {
			t.Errorf("precedence %d at %d", a.Precedence, i)
		}
	}
	if got := Inheritance([]SOM{dom, ou}); !reflect.DeepEqual(names(got), []string{"A@DC=corp", "B@OU=a", "D@DC=corp"}) {
		t.Errorf("ou: %v", names(got))
	}
	// Block inheritance drops every unenforced link above the blocking
	// container, for it and below it, but never an enforced one.
	ou.Block = true
	if got := Inheritance([]SOM{dom, ou, child}); !reflect.DeepEqual(names(got), []string{"A@DC=corp", "C@OU=b", "B@OU=b", "B@OU=a"}) {
		t.Errorf("block at a: %v", names(got))
	}
	ou.Block, child.Block = false, true
	if got := Inheritance([]SOM{dom, ou, child}); !reflect.DeepEqual(names(got), []string{"A@DC=corp", "C@OU=b", "B@OU=b"}) {
		t.Errorf("block at b: %v", names(got))
	}
}

// stubConn answers a base search with base, any other with list, or every one with err.
type stubConn struct {
	base, list *ldap.SearchResult
	err        error
}

func (s stubConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if r.Scope == ldap.ScopeBaseObject {
		return s.base, s.err
	}
	return s.list, s.err
}
func (stubConn) IsClosing() bool          { return false }
func (stubConn) SetTimeout(time.Duration) {}
func (stubConn) Close() error             { return nil }

func TestPSOProbe(t *testing.T) {
	root := &RootDSE{DefaultNamingContext: corpDN}
	entry := func(dn string, attrs map[string][]string) *ldap.SearchResult {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(dn+PSOContainer+","+corpDN, attrs)}}
	}
	pso := func(attrs map[string][]string) *ldap.SearchResult { return entry("CN=p,", attrs) }
	psc := entry("", map[string][]string{"objectClass": {"top", "msDS-PasswordSettingsContainer"}})
	for name, tc := range map[string]struct {
		conn    stubConn
		missing bool
	}{
		"readable":          {stubConn{base: psc, list: pso(map[string][]string{"msDS-PasswordSettingsPrecedence": {"10"}})}, false},
		"no psos":           {stubConn{base: psc, list: &ldap.SearchResult{}}, false},
		"settings hidden":   {stubConn{base: psc, list: pso(nil)}, true},
		"container unread":  {stubConn{base: entry("", nil), list: &ldap.SearchResult{}}, true},
		"container hidden":  {stubConn{err: ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))}, true},
		"access refused":    {stubConn{err: ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))}, true},
		"undecided: broken": {stubConn{err: ldap.NewError(ldap.ErrorNetwork, errors.New("reset"))}, false},
	} {
		if err := ReadProbes["pso-read"](tc.conn, root); (err != nil) != tc.missing {
			t.Errorf("%s: %v", name, err)
		}
	}
}
