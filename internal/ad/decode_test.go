package ad

import (
	"encoding/json"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Worked examples: S-1-5-21-1-2-3-1104 and the GUID from MS-DTYP 2.3.4.
var (
	sidBytes  = string([]byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x50, 4, 0, 0})
	guidBytes = string([]byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
)

func decoded(t *testing.T, attrs map[string][]string, named ...string) string {
	t.Helper()
	b, err := json.Marshal(Decode(ldap.NewEntry("CN=u,DC=corp,DC=example,DC=com", attrs), named))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDecode(t *testing.T) {
	for name, tc := range map[string]struct {
		attrs map[string][]string
		named []string
		want  string
	}{
		"sid": {map[string][]string{"objectSid": {sidBytes}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","objectSid":"S-1-5-21-1-2-3-1104"}`},
		"guid": {map[string][]string{"objectGUID": {guidBytes}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","objectGUID":"00112233-4455-6677-8899-aabbccddeeff"}`},
		// 2026-01-01T00:00:00Z is 134116992000000000 in FILETIME ticks.
		"filetime": {map[string][]string{"pwdLastSet": {"134116992000000000"}, "accountExpires": {"0"},
			"lockoutTime": {"9223372036854775807"}}, nil,
			`{"accountExpires":null,"dn":"CN=u,DC=corp,DC=example,DC=com","lockoutTime":null,"pwdLastSet":"2026-01-01T00:00:00Z"}`},
		"generalized time": {map[string][]string{"whenCreated": {"20260102030405.0Z"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","whenCreated":"2026-01-02T03:04:05Z"}`},
		// 42 days, 30 minutes, never.
		"intervals": {map[string][]string{"maxPwdAge": {"-36288000000000"}, "lockoutDuration": {"-18000000000"},
			"lockOutObservationWindow": {"-9223372036854775808"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","lockOutObservationWindow":null,"lockoutDuration":"PT30M","maxPwdAge":"P42D"}`},
		"uac disabled": {map[string][]string{"userAccountControl": {"66050"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","enabled":false,"userAccountControl":["ACCOUNTDISABLE","NORMAL_ACCOUNT","DONT_EXPIRE_PASSWORD"]}`},
		"uac enabled": {map[string][]string{"userAccountControl": {"4096"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","enabled":true,"userAccountControl":["WORKSTATION_TRUST_ACCOUNT"]}`},
		"group type": {map[string][]string{"groupType": {"-2147483646"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","groupType":{"scope":"global","type":"security"}}`},
		"binary omitted": {map[string][]string{"thumbnailPhoto": {"\xff\xd8\xff"}, "cn": {"u"}}, nil,
			`{"cn":"u","dn":"CN=u,DC=corp,DC=example,DC=com"}`},
		"binary named": {map[string][]string{"thumbnailPhoto": {"\xff\xd8\xff"}}, []string{"thumbnailphoto"},
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","thumbnailPhoto":"/9j/"}`},
		"multi-valued": {map[string][]string{"objectClass": {"top"}, "servicePrincipalName": {"a/b", "c/d"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","objectClass":["top"],"servicePrincipalName":["a/b","c/d"]}`},
		"gPLink": {map[string][]string{"gPLink": {"[LDAP://cn={A},cn=policies,cn=system,DC=x;0][LDAP://cn={B},cn=policies,cn=system,DC=x;2]"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","gPLink":[{"gpo":"cn={B},cn=policies,cn=system,DC=x","link_order":1,"enforced":true,"disabled":false},` +
				`{"gpo":"cn={A},cn=policies,cn=system,DC=x","link_order":2,"enforced":false,"disabled":false}]}`},
		"pwdProperties": {map[string][]string{"pwdProperties": {"17"}, "msDS-PSOAppliesTo": {"CN=g"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","msDS-PSOAppliesTo":["CN=g"],"pwdProperties":["DOMAIN_PASSWORD_COMPLEX","DOMAIN_PASSWORD_STORE_CLEARTEXT"]}`},
		"computed uac": {map[string][]string{"msDS-User-Account-Control-Computed": {"8388624"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","msDS-User-Account-Control-Computed":["LOCKOUT","PASSWORD_EXPIRED"]}`},
		"trust": {map[string][]string{"trustDirection": {"3"}, "trustType": {"2"}, "trustAttributes": {"8"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","trustAttributes":["FOREST_TRANSITIVE"],"trustDirection":"bidirectional","trustType":"uplevel"}`},
		"ranged name": {map[string][]string{"member;range=0-1": {"CN=a", "CN=b"}}, nil,
			`{"dn":"CN=u,DC=corp,DC=example,DC=com","member":["CN=a","CN=b"]}`},
	} {
		if got := decoded(t, tc.attrs, tc.named...); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, tc.want)
		}
	}
}

func TestSIDAndGUIDParse(t *testing.T) {
	if b, err := SIDBytes("S-1-5-21-1-2-3-1104"); err != nil || string(b) != sidBytes {
		t.Errorf("SIDBytes: %x %v", b, err)
	}
	if b, err := GUIDBytes("{00112233-4455-6677-8899-AABBCCDDEEFF}"); err != nil || string(b) != guidBytes {
		t.Errorf("GUIDBytes: %x %v", b, err)
	}
	for _, bad := range []string{"S-1", "S-x-5", "S-1-5-x"} {
		if _, err := SIDBytes(bad); err == nil {
			t.Errorf("SIDBytes(%q): want an error", bad)
		}
	}
}
