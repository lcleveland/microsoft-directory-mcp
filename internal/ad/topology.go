package ad

import (
	"cmp"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Topology from the configuration partition, and the reads that sweep every
// DC: replication status and where a user's lockout came from. LDAP facts
// only (docs/adr/0003).

// dsa is a DC as the configuration partition records it: an nTDSDSA object
// under its server object, under its site.
type dsa struct {
	ntds, host, site string
	gc               bool
	ncs              []string // the naming contexts it holds in full
	inv              string   // invocationId, canonical
}

// dsas reads every DC of the forest.
// ponytail: unpaged, so AD's MaxPageSize (1000 entries) caps it at 500 DCs; page it past that.
func dsas(conn Conn, conf string) ([]dsa, error) {
	res, err := conn.Search(ldap.NewSearchRequest("CN=Sites,"+conf, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=server)(objectClass=nTDSDSA))", []string{"objectClass", "dNSHostName", "options", "hasMasterNCs",
			"msDS-hasMasterNCs", "msDS-hasFullReplicaNCs", "invocationId"}, nil))
	if err != nil {
		return nil, fmt.Errorf("reading DCs from the configuration partition: %w", err)
	}
	hosts := map[string]string{}
	for _, e := range res.Entries {
		hosts[strings.ToLower(e.DN)] = e.GetEqualFoldAttributeValue("dNSHostName")
	}
	var out []dsa
	for _, e := range res.Entries {
		if !slices.ContainsFunc(e.GetEqualFoldAttributeValues("objectClass"), func(c string) bool { return strings.EqualFold(c, "nTDSDSA") }) {
			continue
		}
		_, server, _ := strings.Cut(e.DN, ",")
		d := dsa{ntds: e.DN, host: hosts[strings.ToLower(server)]}
		if p, err := ldap.ParseDN(e.DN); err == nil && len(p.RDNs) > 3 { // NTDS Settings, server, Servers, site
			d.site = p.RDNs[3].Attributes[0].Value
		}
		n, _ := strconv.Atoi(e.GetEqualFoldAttributeValue("options"))
		d.gc = n&1 != 0 // NTDSDSA_OPT_IS_GC
		for _, a := range []string{"hasMasterNCs", "msDS-hasMasterNCs", "msDS-hasFullReplicaNCs"} {
			d.ncs = append(d.ncs, e.GetEqualFoldAttributeValues(a)...)
		}
		if inv := e.GetEqualFoldRawAttributeValue("invocationId"); len(inv) == 16 {
			d.inv = GUIDString(inv)
		}
		out = append(out, d)
	}
	return out, nil
}

// hostOf is the dNSHostName of the DC whose nTDSDSA DN is ntds, or "".
func hostOf(ds []dsa, ntds string) string {
	for _, d := range ds {
		if strings.EqualFold(d.ntds, ntds) {
			return d.host
		}
	}
	return ""
}

// config returns the forest root domain's connection and every DC.
func (c *Client) config(ctx context.Context) (Conn, *RootDSE, []dsa, error) {
	conn, _, root, err := c.Root(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	ds, err := dsas(conn, root.ConfigurationNamingContext)
	return conn, root, ds, err
}

// pick is every domain of the forest, or only the one named by domain.
func (c *Client) pick(ctx context.Context, domain string) ([]Domain, error) {
	if domain == "" {
		return c.Domains(ctx)
	}
	d, err := c.Lookup(ctx, domain)
	return []Domain{d}, err
}

// DC is one domain controller of the forest.
type DC struct {
	Host      string `json:"dNSHostName"`
	Domain    string `json:"domain"`
	Site      string `json:"site"`
	GC        bool   `json:"isGC"`
	PDC       bool   `json:"isPDC"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"` // why it is unreachable
}

// DCs lists the DCs of the forest, or only domain's, from the configuration
// partition, dialing each (a few at a time) to say whether it is reachable.
// A domain that can't be reached is skipped from the PDC check only.
func (c *Client) DCs(ctx context.Context, domain string) ([]DC, []Skipped, error) {
	_, _, all, err := c.config(ctx)
	if err != nil {
		return nil, nil, err
	}
	doms, err := c.pick(ctx, domain)
	if err != nil {
		return nil, nil, err
	}
	pdcs, skipped, err := FanOut(ctx, c, domain, func(conn Conn, d Domain) ([]string, error) {
		owner, err := readAttr(conn, d.DN, "fSMORoleOwner")
		return []string{owner}, err
	})
	if err != nil {
		return nil, nil, err
	}
	static, _ := c.detect(ctx) // an unreachable --ad-dc host shows unreachable below anyway
	var (
		out   []DC
		addrs []string
	)
	for _, x := range all {
		dc := DC{Host: x.host, Site: x.site, GC: x.gc, PDC: slices.ContainsFunc(pdcs, func(o string) bool { return strings.EqualFold(o, x.ntds) })}
		for _, d := range doms {
			if slices.ContainsFunc(x.ncs, func(n string) bool { return strings.EqualFold(n, d.DN) }) {
				dc.Domain = d.DNS
			}
		}
		if dc.Domain == "" && domain != "" {
			continue
		}
		addr := c.addr(x.host, false)
		for _, s := range static { // an --ad-dc host keeps its port
			if strings.EqualFold(s.ntds, x.ntds) {
				addr = s.addr
			}
		}
		out, addrs = append(out, dc), append(addrs, addr)
	}
	each(len(out), perDCLimit, func(i int) {
		conn, err := c.dial(ctx, addrs[i])
		if err != nil {
			out[i].Error = err.Error()
			return
		}
		conn.Close()
		out[i].Reachable = true
	})
	slices.SortFunc(out, func(a, b DC) int { return cmp.Compare(a.Host, b.Host) })
	return out, skipped, nil
}

// Role is a FSMO role and the DC holding it.
type Role struct {
	Role   string `json:"role"`
	Domain string `json:"domain,omitempty"` // for the per-domain roles
	Owner  string `json:"owner"`            // the holder's nTDSDSA DN
	DC     string `json:"dc,omitempty"`     // its dNSHostName
}

// FSMO reads the holders of the forest's two roles (schema, domain_naming)
// and each domain's three (pdc, rid, infrastructure), or only domain's.
func (c *Client) FSMO(ctx context.Context, domain string) ([]Role, []Skipped, error) {
	conn, root, all, err := c.config(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []Role
	if domain == "" {
		for _, r := range [][2]string{{"schema", root.SchemaNamingContext}, {"domain_naming", "CN=Partitions," + root.ConfigurationNamingContext}} {
			owner, err := readAttr(conn, r[1], "fSMORoleOwner")
			if err != nil {
				return nil, nil, err
			}
			out = append(out, Role{Role: r[0], Owner: owner})
		}
	}
	per, skipped, err := FanOut(ctx, c, domain, func(conn Conn, d Domain) ([]Role, error) {
		var rs []Role
		for _, r := range [][2]string{{"pdc", d.DN}, {"rid", "CN=RID Manager$,CN=System," + d.DN}, {"infrastructure", "CN=Infrastructure," + d.DN}} {
			owner, err := readAttr(conn, r[1], "fSMORoleOwner")
			if err != nil {
				return nil, err
			}
			rs = append(rs, Role{Role: r[0], Domain: d.DNS, Owner: owner})
		}
		return rs, nil
	})
	if err != nil {
		return nil, nil, err
	}
	slices.SortStableFunc(per, func(a, b Role) int { return cmp.Compare(a.Domain, b.Domain) })
	out = append(out, per...)
	for i := range out {
		out[i].DC = hostOf(all, out[i].Owner)
	}
	return out, skipped, nil
}

// Site is one site with how many subnets and DCs it has.
type Site struct {
	Name    string `json:"name"`
	Subnets int    `json:"subnets"`
	DCs     int    `json:"dcs"`
}

// Sites lists the forest's sites.
// ponytail: unpaged and counts siteObjectBL unranged, so 1000 sites and 1500 subnets a site; page and range past that.
func (c *Client) Sites(ctx context.Context) ([]Site, error) {
	conn, root, all, err := c.config(ctx)
	if err != nil {
		return nil, err
	}
	res, err := conn.Search(ldap.NewSearchRequest("CN=Sites,"+root.ConfigurationNamingContext, ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=site)", []string{"name", "siteObjectBL"}, nil))
	if err != nil {
		return nil, fmt.Errorf("reading sites: %w", err)
	}
	dcs := map[string]int{}
	for _, d := range all {
		dcs[strings.ToLower(d.site)]++
	}
	out := []Site{}
	for _, e := range res.Entries {
		name := e.GetEqualFoldAttributeValue("name")
		out = append(out, Site{name, len(e.GetEqualFoldAttributeValues("siteObjectBL")), dcs[strings.ToLower(name)]})
	}
	slices.SortFunc(out, func(a, b Site) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

// Neighbor is one inbound replication partner of a DC for one naming
// context (DS_REPL_NEIGHBOR). Times are absent for never.
type Neighbor struct {
	NamingContext string `xml:"pszNamingContext" json:"naming_context"`
	SourceDSA     string `xml:"pszSourceDsaDN" json:"source_dsa"`
	Source        string `xml:"-" json:"source_dc,omitempty"`
	LastSuccess   string `xml:"ftimeLastSyncSuccess" json:"last_success,omitempty"`
	LastAttempt   string `xml:"ftimeLastSyncAttempt" json:"last_attempt,omitempty"`
	LastResult    int    `xml:"dwLastSyncResult" json:"last_result"` // a Win32 error code, 0 for success
	Failures      int    `xml:"cNumConsecutiveSyncFailures" json:"consecutive_failures"`
}

// DSAFailure is a DC the KCC failed to reach (DS_REPL_KCC_DSA_FAILURE).
type DSAFailure struct {
	DSA          string `xml:"pszDsaDN" json:"dsa"`
	Source       string `xml:"-" json:"dc,omitempty"`
	FirstFailure string `xml:"ftimeFirstFailure" json:"first_failure,omitempty"`
	Failures     int    `xml:"cNumFailures" json:"failures"`
	LastResult   int    `xml:"dwLastResult" json:"last_result"`
}

// Repl is one DC's replication status, from its rootDSE.
type Repl struct {
	DC                 string       `json:"dc"`
	Inbound            []Neighbor   `json:"inbound"`
	ConnectionFailures []DSAFailure `json:"connection_failures"`
	LinkFailures       []DSAFailure `json:"link_failures"`
	PendingOps         int          `json:"pending_ops"`
}

// Replication reads every DC's replication status (or only domain's DCs')
// from its rootDSE msDS-Repl* attributes, one short-lived connection each.
func (c *Client) Replication(ctx context.Context, domain string) ([]Repl, []Skipped, error) {
	_, _, all, err := c.config(ctx)
	if err != nil {
		return nil, nil, err
	}
	doms, err := c.pick(ctx, domain)
	if err != nil {
		return nil, nil, err
	}
	var (
		out     []Repl
		skipped []Skipped
	)
	// ponytail: one domain's DCs at a time; sweep domains in parallel if a large forest makes this slow.
	for _, d := range doms {
		rs, sk, err := PerDC(ctx, c, d, func(conn Conn, dc string) (Repl, error) { return readRepl(conn, dc, all) })
		if err != nil {
			return nil, nil, err
		}
		out, skipped = append(out, rs...), append(skipped, sk...)
	}
	slices.SortFunc(out, func(a, b Repl) int { return cmp.Compare(a.DC, b.DC) })
	return out, skipped, nil
}

func readRepl(conn Conn, dc string, all []dsa) (Repl, error) {
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)",
		[]string{"msDS-ReplAllInboundNeighbors", "msDS-ReplConnectionFailures", "msDS-ReplLinkFailures", "msDS-ReplPendingOps"}, nil))
	if err != nil {
		return Repl{}, fmt.Errorf("reading rootDSE: %w", err)
	}
	if len(res.Entries) != 1 {
		return Repl{}, fmt.Errorf("reading rootDSE: %d entries", len(res.Entries))
	}
	e := res.Entries[0]
	r := Repl{DC: dc, PendingOps: len(e.GetEqualFoldAttributeValues("msDS-ReplPendingOps"))}
	if r.Inbound, err = xmlValues[Neighbor](e, "msDS-ReplAllInboundNeighbors"); err != nil {
		return Repl{}, err
	}
	if r.ConnectionFailures, err = xmlValues[DSAFailure](e, "msDS-ReplConnectionFailures"); err != nil {
		return Repl{}, err
	}
	if r.LinkFailures, err = xmlValues[DSAFailure](e, "msDS-ReplLinkFailures"); err != nil {
		return Repl{}, err
	}
	for i := range r.Inbound {
		n := &r.Inbound[i]
		n.Source, n.LastSuccess, n.LastAttempt = hostOf(all, n.SourceDSA), never(n.LastSuccess), never(n.LastAttempt)
	}
	for _, fs := range [][]DSAFailure{r.ConnectionFailures, r.LinkFailures} {
		for i := range fs {
			fs[i].Source, fs[i].FirstFailure = hostOf(all, fs[i].DSA), never(fs[i].FirstFailure)
		}
	}
	return r, nil
}

// xmlValues decodes each value of attr, an msDS-Repl* XML fragment.
func xmlValues[T any](e *ldap.Entry, attr string) ([]T, error) {
	out := []T{}
	for _, v := range e.GetEqualFoldAttributeValues(attr) {
		var t T
		if err := xml.Unmarshal([]byte(strings.TrimRight(v, "\x00\n")), &t); err != nil {
			return nil, fmt.Errorf("%s: %w", attr, err)
		}
		out = append(out, t)
	}
	return out, nil
}

// never blanks the FILETIME zero (1601) the msDS-Repl* XML uses for never.
func never(t string) string {
	if strings.HasPrefix(t, "1601-") {
		return ""
	}
	return t
}

// Origin is the last originating write of an attribute (DS_REPL_ATTR_META_DATA).
type Origin struct {
	Attribute    string `xml:"pszAttributeName" json:"-"`
	DC           string `xml:"-" json:"dc,omitempty"`
	DSA          string `xml:"pszLastOriginatingDsaDN" json:"dsa,omitempty"`
	InvocationID string `xml:"uuidLastOriginatingDsaInvocationID" json:"invocation_id"`
	Time         string `xml:"ftimeLastOriginatingChange" json:"time"`
	Version      int    `xml:"dwVersion" json:"version"`
}

// lockoutTimeAttid is lockoutTime's attid: prefix 9 of the static prefix
// table (1.2.840.113556.1.4) and 662.
const lockoutTimeAttid = 9<<16 | 662

// origin finds attr's last originating write in msDS-ReplAttributeMetaData,
// else (Samba constructs no such attribute) by attid in the binary
// replPropertyMetaData. It is nil when neither holds it.
func origin(e *ldap.Entry, attr string, attid uint32) (*Origin, error) {
	ms, err := xmlValues[Origin](e, "msDS-ReplAttributeMetaData")
	if err != nil {
		return nil, err
	}
	for _, o := range ms {
		if strings.EqualFold(o.Attribute, attr) {
			return &o, nil
		}
	}
	// Version 1, a reserved word, the count, another, then 48-byte entries:
	// attid, version, change time (seconds since 1601), invocation ID, two USNs.
	b := e.GetEqualFoldRawAttributeValue("replPropertyMetaData")
	if len(b) < 16 || binary.LittleEndian.Uint32(b) != 1 {
		return nil, nil
	}
	for i := range int(binary.LittleEndian.Uint32(b[8:])) {
		m := b[min(16+48*i, len(b)):]
		if len(m) < 48 {
			return nil, nil
		}
		if binary.LittleEndian.Uint32(m) == attid {
			secs := int64(binary.LittleEndian.Uint64(m[8:])) - 11644473600
			return &Origin{Version: int(binary.LittleEndian.Uint32(m[4:])), InvocationID: GUIDString(m[16:32]),
				Time: time.Unix(secs, 0).UTC().Format(time.RFC3339)}, nil
		}
	}
	return nil, nil
}

// LockoutAttrs are what Lockout needs read of the user.
var LockoutAttrs = []string{"lockoutTime", "msDS-User-Account-Control-Computed", "msDS-ReplAttributeMetaData", "replPropertyMetaData"}

// Lockout is a user's lockout as LDAP shows it. The machine that caused it
// (event 4740) is not among it.
type Lockout struct {
	DN          string           `json:"dn"`
	LockoutTime any              `json:"lockoutTime"`
	LockedOut   bool             `json:"locked_out"`
	Computed    any              `json:"msDS-User-Account-Control-Computed"`
	Origin      *Origin          `json:"lockoutTime_origin"`
	PerDC       []map[string]any `json:"per_dc"`
	Skipped     []Skipped        `json:"_skipped,omitempty"`
}

// Lockout reads a user's lockout from e (read with LockoutAttrs): the DC
// that originated its last lockoutTime write, and badPwdCount and
// badPasswordTime, which don't replicate, from every DC of its domain.
func (c *Client) Lockout(ctx context.Context, e *ldap.Entry) (*Lockout, error) {
	m := Decode(e, nil)
	_, computed := Field(m, "msDS-User-Account-Control-Computed")
	_, lt := Field(m, "lockoutTime")
	flags, _ := computed.([]string)
	l := &Lockout{DN: e.DN, LockoutTime: lt, Computed: computed, LockedOut: slices.Contains(flags, "LOCKOUT")}
	var err error
	if l.Origin, err = origin(e, "lockoutTime", lockoutTimeAttid); err != nil {
		return nil, err
	}
	if l.Origin != nil {
		_, _, all, err := c.config(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range all {
			if l.Origin.DSA == "" && strings.EqualFold(d.inv, l.Origin.InvocationID) {
				l.Origin.DSA = d.ntds
			}
		}
		l.Origin.DC = hostOf(all, l.Origin.DSA)
	}
	d, err := c.DomainOf(ctx, e.DN)
	if err != nil {
		return nil, err
	}
	attrs := []string{"badPwdCount", "badPasswordTime"}
	l.PerDC, l.Skipped, err = PerDC(ctx, c, d, func(conn Conn, dc string) (map[string]any, error) {
		res, err := conn.Search(ldap.NewSearchRequest(e.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", attrs, nil))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return map[string]any{"dc": dc, "note": "the user has not replicated here yet"}, nil
		}
		if err != nil {
			return nil, err
		}
		if len(res.Entries) != 1 {
			return nil, fmt.Errorf("%s: %d entries", e.DN, len(res.Entries))
		}
		m := Decode(res.Entries[0], attrs)
		delete(m, "dn")
		m["dc"] = dc
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(l.PerDC, func(a, b map[string]any) int { return cmp.Compare(a["dc"].(string), b["dc"].(string)) })
	return l, nil
}
