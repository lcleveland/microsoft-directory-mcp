package ad

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// Value rendering: keys keep their LDAP names, values are decoded. The kind
// of an attribute comes from these lists, by lowercased name.
var (
	sidAttrs  = set("objectSid", "sIDHistory", "tokenGroups", "securityIdentifier", "mS-DS-CreatorSID")
	guidAttrs = set("objectGUID", "schemaIDGUID", "attributeSecurityGUID", "msExchMailboxGuid", "msDS-ConsistencyGuid", "mS-DS-ConsistencyGuid")
	fileTimes = set("pwdLastSet", "lastLogon", "lastLogonTimestamp", "lastLogoff", "lockoutTime", "accountExpires",
		"badPasswordTime", "msDS-UserPasswordExpiryTimeComputed", "ms-Mcs-AdmPwdExpirationTime",
		"msLAPS-PasswordExpirationTime", "creationTime", "msDS-LastSuccessfulInteractiveLogonTime")
	genTimes = set("whenCreated", "whenChanged", "dSCorePropagationData", "createTimeStamp", "modifyTimeStamp",
		"msDS-LastKnownRDN-Time", "msTSExpireDate")
	intervals = set("maxPwdAge", "minPwdAge", "lockoutDuration", "lockOutObservationWindow", "forceLogoff",
		"msDS-MaximumPasswordAge", "msDS-MinimumPasswordAge", "msDS-LockoutDuration", "msDS-LockoutObservationWindow")
	// Rendered as lists even with one value. Others are lists only with several.
	// ponytail: a fixed list, not the schema's isSingleValued; read the schema if the inconsistency bites.
	multiValued = set("objectClass", "memberOf", "member", "directReports", "servicePrincipalName", "proxyAddresses",
		"sIDHistory", "tokenGroups", "dSCorePropagationData", "otherTelephone", "otherMobile", "url", "wWWHomePage",
		"msDS-AllowedToDelegateTo", "userWorkstations", "namingContexts", "managedObjects", "gPLink")
)

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[strings.ToLower(n)] = true
	}
	return m
}

// uacFlags are the userAccountControl bits by name, in bit order.
var uacFlags = []struct {
	bit  uint32
	name string
}{
	{0x1, "SCRIPT"}, {0x2, "ACCOUNTDISABLE"}, {0x8, "HOMEDIR_REQUIRED"}, {0x10, "LOCKOUT"},
	{0x20, "PASSWD_NOTREQD"}, {0x40, "PASSWD_CANT_CHANGE"}, {0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"},
	{0x100, "TEMP_DUPLICATE_ACCOUNT"}, {0x200, "NORMAL_ACCOUNT"}, {0x800, "INTERDOMAIN_TRUST_ACCOUNT"},
	{0x1000, "WORKSTATION_TRUST_ACCOUNT"}, {0x2000, "SERVER_TRUST_ACCOUNT"}, {0x10000, "DONT_EXPIRE_PASSWORD"},
	{0x20000, "MNS_LOGON_ACCOUNT"}, {0x40000, "SMARTCARD_REQUIRED"}, {0x80000, "TRUSTED_FOR_DELEGATION"},
	{0x100000, "NOT_DELEGATED"}, {0x200000, "USE_DES_KEY_ONLY"}, {0x400000, "DONT_REQ_PREAUTH"},
	{0x800000, "PASSWORD_EXPIRED"}, {0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"}, {0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

// Decode renders an entry as dn plus its decoded attributes, adding enabled
// when userAccountControl is present. Binary values that aren't SIDs or
// GUIDs are left out unless named (any case), then base64.
func Decode(e *ldap.Entry, named []string) map[string]any {
	out := map[string]any{"dn": e.DN}
	for _, a := range e.Attributes {
		name, _, _ := strings.Cut(a.Name, ";range=") // a ranged attribute keeps its name
		key := strings.ToLower(name)
		var vals []any
		for _, raw := range a.ByteValues {
			v, ok := value(key, raw)
			if !ok {
				if !slices.ContainsFunc(named, func(n string) bool { return strings.EqualFold(n, name) }) {
					break
				}
				v = base64.StdEncoding.EncodeToString(raw)
			}
			vals = append(vals, v)
		}
		switch {
		case len(vals) == 0:
			continue
		case len(vals) == 1 && !multiValued[key]:
			out[name] = vals[0]
		default:
			out[name] = vals
		}
		if key == "useraccountcontrol" {
			n, _ := strconv.ParseUint(string(a.ByteValues[0]), 10, 32)
			out["enabled"] = n&0x2 == 0
		}
	}
	return out
}

// value decodes one raw value of the attribute key (lowercased). ok is false
// for a binary value it can't render.
func value(key string, raw []byte) (any, bool) {
	s := string(raw)
	switch {
	case sidAttrs[key]:
		return SIDString(raw), true
	case guidAttrs[key] && len(raw) == 16:
		return GUIDString(raw), true
	case fileTimes[key]:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || n == math.MaxInt64 {
			return nil, true
		}
		return time.Unix(n/1e7-11644473600, n%1e7*100).UTC().Format(time.RFC3339), true
	case intervals[key]:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n == math.MinInt64 {
			return nil, true // never
		}
		return isoDuration(time.Duration(-n) * 100), true
	case key == "useraccountcontrol":
		n, _ := strconv.ParseUint(s, 10, 32)
		flags := []string{}
		for _, f := range uacFlags {
			if uint32(n)&f.bit != 0 {
				flags = append(flags, f.name)
			}
		}
		return flags, true
	case key == "grouptype":
		n, _ := strconv.ParseInt(s, 10, 32)
		g := map[string]string{"scope": "global", "type": "distribution"}
		switch {
		case n&0x4 != 0:
			g["scope"] = "domain_local"
		case n&0x8 != 0:
			g["scope"] = "universal"
		}
		if n < 0 { // 0x80000000
			g["type"] = "security"
		}
		return g, true
	case genTimes[key]:
		t, err := time.Parse("20060102150405.0Z0700", s)
		if err != nil {
			return s, true
		}
		if t.Year() <= 1601 {
			return nil, true
		}
		return t.UTC().Format(time.RFC3339), true
	}
	if !utf8.Valid(raw) {
		return nil, false
	}
	return s, true
}

// isoDuration renders d as an ISO 8601 duration, days being 24 hours.
func isoDuration(d time.Duration) string {
	if d <= 0 {
		return "PT0S"
	}
	s := "P"
	if days := d / (24 * time.Hour); days > 0 {
		s += fmt.Sprintf("%dD", days)
		d -= days * 24 * time.Hour
	}
	if d == 0 {
		return s
	}
	s += "T"
	for _, u := range []struct {
		d time.Duration
		c string
	}{{time.Hour, "H"}, {time.Minute, "M"}, {time.Second, "S"}} {
		if n := d / u.d; n > 0 {
			s += fmt.Sprintf("%d%s", n, u.c)
			d -= n * u.d
		}
	}
	return s
}

// SIDString renders a binary SID as S-1-….
func SIDString(b []byte) string {
	if len(b) < 8 || len(b) < 8+4*int(b[1]) {
		return base64.StdEncoding.EncodeToString(b)
	}
	auth := uint64(0)
	for _, x := range b[2:8] {
		auth = auth<<8 | uint64(x)
	}
	s := fmt.Sprintf("S-%d-%d", b[0], auth)
	for i := range int(b[1]) {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s
}

// SIDBytes parses S-1-… into its binary form.
func SIDBytes(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") || len(parts) > 3+15 {
		return nil, fmt.Errorf("SID %q: not S-1-…", s)
	}
	rev, err1 := strconv.ParseUint(parts[1], 10, 8)
	auth, err2 := strconv.ParseUint(parts[2], 10, 48)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("SID %q: not S-1-…", s)
	}
	b := []byte{byte(rev), byte(len(parts) - 3)}
	b = binary.BigEndian.AppendUint64(b, auth)
	b = append(b[:2], b[4:]...) // 48-bit authority
	for _, p := range parts[3:] {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("SID %q: sub-authority %q", s, p)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
	}
	return b, nil
}

// GUIDString renders a binary GUID in canonical form (its first three
// groups are little-endian).
func GUIDString(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

// GUIDBytes parses a canonical GUID, braces optional, into its binary form.
func GUIDBytes(s string) ([]byte, error) {
	h := strings.ReplaceAll(strings.Trim(s, "{}"), "-", "")
	if len(h) != 32 {
		return nil, fmt.Errorf("GUID %q: not canonical", s)
	}
	var raw [16]byte
	for i := range raw {
		n, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("GUID %q: not canonical", s)
		}
		raw[i] = byte(n)
	}
	b := binary.LittleEndian.AppendUint32(nil, binary.BigEndian.Uint32(raw[:]))
	b = binary.LittleEndian.AppendUint16(b, binary.BigEndian.Uint16(raw[4:]))
	b = binary.LittleEndian.AppendUint16(b, binary.BigEndian.Uint16(raw[6:]))
	return append(b, raw[8:]...), nil
}

// escapeBytes escapes every byte of a binary filter value.
func escapeBytes(b []byte) string {
	var sb strings.Builder
	for _, x := range b {
		fmt.Fprintf(&sb, "\\%02x", x)
	}
	return sb.String()
}
