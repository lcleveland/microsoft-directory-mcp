package ad

import (
	"context"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

const pwdLastSetAttid = 9<<16 | 96

// metaBlob builds a replPropertyMetaData value: version 1, then 48-byte
// entries of attid, version, change time (seconds since 1601), invocation ID
// and two USNs.
func metaBlob(entries ...struct {
	attid, version uint32
	secs           uint64
	inv            []byte
}) string {
	b := binary.LittleEndian.AppendUint32(nil, 1)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(entries)))
	b = binary.LittleEndian.AppendUint32(b, 0)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint32(b, e.attid)
		b = binary.LittleEndian.AppendUint32(b, e.version)
		b = binary.LittleEndian.AppendUint64(b, e.secs)
		b = append(b, e.inv...)
		b = binary.LittleEndian.AppendUint64(b, 100)
		b = binary.LittleEndian.AppendUint64(b, 200)
	}
	return string(b)
}

type metaEntry = struct {
	attid, version uint32
	secs           uint64
	inv            []byte
}

// 2026-01-02T03:04:05Z in seconds since 1601.
const lockedSecs = 1767323045 + 11644473600

func TestOriginFromXML(t *testing.T) {
	e := ldap.NewEntry("CN=u,"+corpDN, map[string][]string{"msDS-ReplAttributeMetaData": {
		"<DS_REPL_ATTR_META_DATA>\n\t<pszAttributeName>pwdLastSet</pszAttributeName>\n\t<dwVersion>1</dwVersion>\n" +
			"\t<ftimeLastOriginatingChange>2025-01-01T00:00:00Z</ftimeLastOriginatingChange>\n</DS_REPL_ATTR_META_DATA>\n\x00",
		"<DS_REPL_ATTR_META_DATA>\n\t<pszAttributeName>lockoutTime</pszAttributeName>\n\t<dwVersion>4</dwVersion>\n" +
			"\t<ftimeLastOriginatingChange>2026-01-02T03:04:05Z</ftimeLastOriginatingChange>\n" +
			"\t<uuidLastOriginatingDsaInvocationID>0f0e0d0c-0b0a-0908-0706-050403020100</uuidLastOriginatingDsaInvocationID>\n" +
			"\t<usnOriginatingChange>12345</usnOriginatingChange>\n\t<usnLocalChange>12345</usnLocalChange>\n" +
			"\t<pszLastOriginatingDsaDN>" + ntds("dc2") + "</pszLastOriginatingDsaDN>\n</DS_REPL_ATTR_META_DATA>\n\x00",
	}})
	got, err := origin(e, "lockoutTime", lockoutTimeAttid)
	want := &Origin{Attribute: "lockoutTime", DSA: ntds("dc2"), InvocationID: "0f0e0d0c-0b0a-0908-0706-050403020100",
		Time: "2026-01-02T03:04:05Z", Version: 4}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v %v", got, err)
	}
	bad := ldap.NewEntry("CN=u,"+corpDN, map[string][]string{"msDS-ReplAttributeMetaData": {"<DS_REPL"}})
	if _, err := origin(bad, "lockoutTime", lockoutTimeAttid); err == nil {
		t.Error("broken XML: want an error")
	}
}

// Samba has no msDS-ReplAttributeMetaData: the binary replPropertyMetaData, by attid.
func TestOriginFromBinary(t *testing.T) {
	blob := metaBlob(metaEntry{pwdLastSetAttid, 1, 1, invocation("dc1")}, metaEntry{lockoutTimeAttid, 3, lockedSecs, invocation("dc3")})
	e := ldap.NewEntry("CN=u,"+corpDN, map[string][]string{"replPropertyMetaData": {blob}})
	got, err := origin(e, "lockoutTime", lockoutTimeAttid)
	want := &Origin{InvocationID: GUIDString(invocation("dc3")), Time: "2026-01-02T03:04:05Z", Version: 3}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v %v", got, err)
	}
	for _, short := range []string{"", blob[:16], blob[:16+48+20]} {
		e := ldap.NewEntry("CN=u,"+corpDN, map[string][]string{"replPropertyMetaData": {short}})
		if got, err := origin(e, "lockoutTime", lockoutTimeAttid); got != nil || err != nil {
			t.Errorf("%d bytes: %+v %v", len(short), got, err)
		}
	}
}

// The lockout of a child-domain user locked out on dc3: the origin resolved
// from its invocation ID to dc3, badPwdCount from dc3 alone, dc4 skipped.
func TestLockoutSweepsEveryDC(t *testing.T) {
	f := newFakeDir()
	f.kill("dc4.child.corp.example.com")
	user := strings.ToLower("CN=locked,CN=Users," + childDN)
	f.tree[user] = map[string][]string{"objectClass": {"user"}, "lockoutTime": {"134117966450000000"},
		"msDS-User-Account-Control-Computed": {"16"},
		"replPropertyMetaData":               {metaBlob(metaEntry{lockoutTimeAttid, 3, lockedSecs, invocation("dc3")})}}
	f.local["dc3.child.corp.example.com "+user] = map[string][]string{"badPwdCount": {"5"}, "badPasswordTime": {"134117966450000000"}}
	c := f.client(srvConfig())
	ctx := context.Background()
	e, err := c.Get(ctx, user, "(objectClass=user)", LockoutAttrs)
	if err != nil {
		t.Fatal(err)
	}
	l, err := c.Lockout(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if !l.LockedOut || l.LockoutTime != "2026-01-02T03:04:05Z" {
		t.Errorf("lockout: %+v", l)
	}
	if o := l.Origin; o == nil || o.DC != "dc3.child.corp.example.com" || !strings.EqualFold(o.DSA, ntds("dc3")) || o.Version != 3 {
		t.Errorf("origin: %+v", o)
	}
	want := []map[string]any{{"dc": "dc3.child.corp.example.com:636", "badPwdCount": "5", "badPasswordTime": "2026-01-02T03:04:05Z"}}
	if !reflect.DeepEqual(l.PerDC, want) {
		t.Errorf("per DC: %v", l.PerDC)
	}
	if len(l.Skipped) != 1 || l.Skipped[0].DC != "dc4.child.corp.example.com:636" {
		t.Errorf("skipped: %+v", l.Skipped)
	}
}

func TestDCs(t *testing.T) {
	f := newFakeDir()
	f.kill("dc4.child.corp.example.com")
	c := f.client(srvConfig())
	ctx := context.Background()
	got, skipped, err := c.DCs(ctx, "")
	if err != nil || skipped != nil {
		t.Fatal(skipped, err)
	}
	for i := range got {
		if got[i].Error != "" {
			got[i].Error = "x"
		}
	}
	// The site comes from the nTDSDSA DN, which the fake lowercases.
	want := []DC{
		{Host: "dc1.corp.example.com", Domain: "corp.example.com", Site: "site1", GC: true, Reachable: true},
		{Host: "dc2.corp.example.com", Domain: "corp.example.com", Site: "site1", PDC: true, Reachable: true},
		{Host: "dc3.child.corp.example.com", Domain: "child.corp.example.com", Site: "site1", PDC: true, Reachable: true},
		{Host: "dc4.child.corp.example.com", Domain: "child.corp.example.com", Site: "site1", Error: "x"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if got, _, err := c.DCs(ctx, "child"); err != nil || len(got) != 2 || got[0].Domain != "child.corp.example.com" {
		t.Errorf("child only: %+v %v", got, err)
	}
}

func TestFSMO(t *testing.T) {
	f := newFakeDir()
	set := func(dn, dc string) { f.tree[strings.ToLower(dn)] = map[string][]string{"fSMORoleOwner": {ntds(dc)}} }
	set("CN=Schema,"+confDN, "dc1")
	set("CN=Partitions,"+confDN, "dc1")
	for dom, dc := range map[string]string{corpDN: "dc2", childDN: "dc4"} {
		set("CN=RID Manager$,CN=System,"+dom, dc)
		set("CN=Infrastructure,"+dom, dc)
	}
	f.roots["dc1.corp.example.com"]["schemaNamingContext"] = []string{"CN=Schema," + confDN}
	c := f.client(srvConfig())
	got, _, err := c.FSMO(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var brief []string
	for _, r := range got {
		brief = append(brief, r.Role+" "+r.Domain+" "+r.DC)
	}
	want := []string{"schema  dc1.corp.example.com", "domain_naming  dc1.corp.example.com",
		"pdc child.corp.example.com dc3.child.corp.example.com", "rid child.corp.example.com dc4.child.corp.example.com",
		"infrastructure child.corp.example.com dc4.child.corp.example.com",
		"pdc corp.example.com dc2.corp.example.com", "rid corp.example.com dc2.corp.example.com",
		"infrastructure corp.example.com dc2.corp.example.com"}
	if !reflect.DeepEqual(brief, want) {
		t.Errorf("got  %q\nwant %q", brief, want)
	}
}

func TestReplication(t *testing.T) {
	f := newFakeDir()
	f.roots["dc1.corp.example.com"]["msDS-ReplAllInboundNeighbors"] = []string{"<DS_REPL_NEIGHBOR>\n" +
		"\t<pszNamingContext>" + corpDN + "</pszNamingContext>\n\t<pszSourceDsaDN>" + ntds("dc2") + "</pszSourceDsaDN>\n" +
		"\t<ftimeLastSyncSuccess>1601-01-01T00:00:00Z</ftimeLastSyncSuccess>\n" +
		"\t<ftimeLastSyncAttempt>2026-01-02T03:04:05Z</ftimeLastSyncAttempt>\n" +
		"\t<dwLastSyncResult>8524</dwLastSyncResult>\n\t<cNumConsecutiveSyncFailures>7</cNumConsecutiveSyncFailures>\n" +
		"</DS_REPL_NEIGHBOR>\n\x00"}
	f.roots["dc1.corp.example.com"]["msDS-ReplConnectionFailures"] = []string{"<DS_REPL_KCC_DSA_FAILURE>\n" +
		"\t<pszDsaDN>" + ntds("dc2") + "</pszDsaDN>\n\t<ftimeFirstFailure>2026-01-01T00:00:00Z</ftimeFirstFailure>\n" +
		"\t<cNumFailures>7</cNumFailures>\n\t<dwLastResult>1722</dwLastResult>\n</DS_REPL_KCC_DSA_FAILURE>\n"}
	f.roots["dc1.corp.example.com"]["msDS-ReplPendingOps"] = []string{"<DS_REPL_OP/>", "<DS_REPL_OP/>"}
	c := f.client(srvConfig())
	got, skipped, err := c.Replication(context.Background(), "corp")
	if err != nil || skipped != nil {
		t.Fatal(skipped, err)
	}
	want := []Repl{
		{DC: "dc1.corp.example.com:636", PendingOps: 2,
			Inbound: []Neighbor{{NamingContext: corpDN, SourceDSA: ntds("dc2"), Source: "dc2.corp.example.com",
				LastAttempt: "2026-01-02T03:04:05Z", LastResult: 8524, Failures: 7}},
			ConnectionFailures: []DSAFailure{{DSA: ntds("dc2"), Source: "dc2.corp.example.com", FirstFailure: "2026-01-01T00:00:00Z", Failures: 7, LastResult: 1722}},
			LinkFailures:       []DSAFailure{}},
		{DC: "dc2.corp.example.com:636", Inbound: []Neighbor{}, ConnectionFailures: []DSAFailure{}, LinkFailures: []DSAFailure{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestSites(t *testing.T) {
	f := newFakeDir()
	f.tree[strings.ToLower("CN=Site1,CN=Sites,"+confDN)] = map[string][]string{"objectClass": {"site"}, "name": {"Site1"},
		"siteObjectBL": {"CN=10.0.0.0/24,CN=Subnets,CN=Sites," + confDN, "CN=10.0.1.0/24,CN=Subnets,CN=Sites," + confDN}}
	f.tree[strings.ToLower("CN=Site2,CN=Sites,"+confDN)] = map[string][]string{"objectClass": {"site"}, "name": {"Site2"}}
	got, err := f.client(srvConfig()).Sites(context.Background())
	want := []Site{{Name: "Site1", Subnets: 2, DCs: 4}, {Name: "Site2"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v %v", got, err)
	}
}
