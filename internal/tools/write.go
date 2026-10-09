package tools

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
)

// The write framework: capabilities, reason and audit, one target per
// write, the operation classifier, the AD rails, and generated passwords.
// See docs/adr/0001-write-capability-map.md.

// writeIn is what every write takes. A parameter described "writes: " or
// "writes, a, b: " is left out of the schema until one of its writes shows.
type writeIn struct {
	Reason  string `json:"reason,omitempty" jsonschema:"writes: why you are making this change; required, and recorded in the audit log"`
	Confirm string `json:"confirm,omitempty" jsonschema:"writes, reset_password, delete: the target's name exactly (its sAMAccountName), to confirm it is the one you mean"`
}

var errReason = errors.New("reason is required for writes: say why, it is recorded in the audit log")

// adOp classifies one kind of AD write: the capability that allows it and
// the first-class action that makes it.
type adOp struct {
	op, attr   string // attr only for modify
	capability string
	action     string
}

// adOps classifies AD writes by operation, and modifies by attribute.
// Anything not here, nor in the ad-objects allowlist, is unmapped: refused.
var adOps = []adOp{
	{"modify", "userAccountControl", "ad-account-state", "ad_user or ad_computer disable or enable"},
	{"modify", "lockoutTime", "ad-account-state", "ad_user unlock"},
	{"modify", "pwdLastSet", "ad-account-state", "ad_user must_change"},
	{"modify", "accountExpires", "ad-account-state", "ad_user set_expiry"},
	{"modify", "unicodePwd", "ad-passwords", "ad_user reset_password"},
	{"modify", "userPassword", "ad-passwords", "ad_user reset_password"},
	{"modify", "member", "ad-group-membership", "ad_group add_members or remove_members"},
	{"modify", "gPLink", "ad-gpo-links", "ad_gpo link"},
	{"modify", "gPOptions", "ad-gpo-links", "ad_gpo block_inheritance"},
	{"modify", "msDS-PSOAppliesTo", "ad-password-policy", "ad_policy apply"},
	{"modify", "isDeleted", "ad-delete", "ad_object restore"},
	{"add", "", "ad-objects", "ad_user, ad_group or ad_computer create"},
	{"delete", "", "ad-delete", "ad_object delete"},
	{"rename", "", "ad-objects", "ad_object rename or move"},
}

// adObjectAttrs is the ad-objects allowlist: by object class, the
// attributes ad_api may modify. The ad-objects issue fills it.
var adObjectAttrs = map[string][]string{}

// classifyAD maps one AD write (op: modify, add, delete or rename; attr
// for a modify) on an object of class (its most specific objectClass) to
// the capability that allows it. raw is ad_api, where a write that a
// first-class action makes is refused and pointed to that action.
func classifyAD(op, attr, class string, raw bool) (string, error) {
	for _, o := range adOps {
		if o.op == op && strings.EqualFold(o.attr, attr) {
			if raw {
				return "", fmt.Errorf("ad_api %s %s: call %s instead (the %s capability)", op, attr, o.action, o.capability)
			}
			return o.capability, nil
		}
	}
	if raw && op == "modify" && slices.ContainsFunc(adObjectAttrs[strings.ToLower(class)], func(a string) bool { return strings.EqualFold(a, attr) }) {
		return "ad-objects", nil
	}
	return "", fmt.Errorf("%s %s on %s is not a write this server makes", op, attr, cmp.Or(class, "this object"))
}

// adWrite is one AD write: an object, by id, and the changes made to it.
type adWrite struct {
	tool, action string
	id, class    string // the target, resolved as reads resolve it
	in           writeIn
	raw          bool     // from ad_api: classified as raw
	confirm      bool     // in.Confirm must name the target
	attrs        []string // read before the write, for changes
	changes      func(*ldap.Entry) ([]ldap.Change, error)
	controls     []ldap.Control
}

// adModify and adProtected are the transport's Modify and Protected; seams for tests.
var (
	adModify    = (*ad.Client).Modify
	adProtected = (*ad.Client).Protected
)

// adWrite runs w through the AD rails. Every AD write goes through here, so
// none skips the reason, the pre-read on the PDC emulator, the protected
// target and source of authority refusals, confirm, the capability its
// changes classify to, or the audit log. Nothing is retried.
func (d Deps) adWrite(ctx context.Context, w adWrite) (map[string]any, error) {
	reason := strings.TrimSpace(w.in.Reason)
	if reason == "" {
		return nil, errReason
	}
	dn, err := d.AD.Resolve(ctx, w.id, w.class)
	if err != nil {
		return nil, err
	}
	audit := []any{"tool", w.tool, "action", w.action, "target", dn, "reason", reason}
	var (
		sent bool
		cp   *Counterpart
	)
	tgt, err := adModify(d.AD, ctx, dn, w.class, w.attrs, func(e *ldap.Entry) (*ldap.ModifyRequest, error) {
		if name := cmp.Or(e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("name")); w.confirm && strings.TrimSpace(w.in.Confirm) != name {
			return nil, fmt.Errorf("confirm must be the target's name exactly: %s is %q. Check it is the object you mean, then retry", e.DN, name)
		}
		changes, err := w.changes(e)
		if err != nil {
			return nil, err
		}
		var caps, names []string
		cls := append([]string{""}, e.GetAttributeValues("objectClass")...)
		for _, ch := range changes {
			c, err := classifyAD("modify", ch.Modification.Type, cls[len(cls)-1], w.raw)
			if err != nil {
				return nil, err
			}
			// A reset's must-change rides on its password write, under ad-passwords.
			if strings.EqualFold(ch.Modification.Type, "pwdLastSet") && slices.ContainsFunc(changes, func(x ldap.Change) bool {
				return strings.EqualFold(x.Modification.Type, "unicodePwd")
			}) {
				c = "ad-passwords"
			}
			if !d.Config.Capabilities[c] {
				return nil, fmt.Errorf("writing %s needs the %s capability, which the operator has not enabled", ch.Modification.Type, c)
			}
			caps, names = append(caps, c), append(names, ch.Modification.Type)
		}
		if cp, err = d.adAuthority(ctx, e); err != nil {
			return nil, err
		}
		slices.Sort(caps)
		slices.Sort(names)
		// Attribute names only: values (passwords among them) are never logged.
		audit = append(audit, "capability", strings.Join(slices.Compact(caps), ","), "attributes", slices.Compact(names))
		// Logged before sending too, so a write cut off mid-call still has a record.
		d.log().Info("ad write", append(audit, "outcome", "sending")...)
		sent = true
		return &ldap.ModifyRequest{DN: e.DN, Changes: changes, Controls: w.controls}, nil
	})
	audit = append(audit, "dc", tgt.DC, "fallback", tgt.Fallback)
	if err != nil {
		outcome := "failed"
		if !sent {
			outcome = "not sent"
		}
		d.log().Warn("ad write", append(audit, "outcome", outcome, "error", err.Error())...)
		return nil, err
	}
	d.log().Info("ad write", append(audit, "outcome", "ok")...)
	out := obj(tgt)
	out["dn"], out["action"] = dn, w.action
	if cp != nil && cp.ID != "" {
		out["sync"] = "the change reaches its Entra counterpart " + cp.ID + " on the next sync cycle, not at once"
	}
	return out, nil
}

// joinOfEntry is the join of a pre-read AD object's class, if any.
func joinOfEntry(e *ldap.Entry) (join, bool) {
	cls := e.GetAttributeValues("objectClass")
	switch {
	case slices.Contains(cls, "computer"):
		return joinDevice, true
	case slices.Contains(cls, "group"):
		return joinGroup, true
	case slices.Contains(cls, "user"):
		return joinUser, true
	}
	return join{}, false
}

// adAuthority refuses an AD write when the target's source of authority is
// the tenant: msDS-ObjectSoa says Cloud, or its Entra counterpart is cloud
// managed. It returns the counterpart, if any. A Graph error fails closed.
func (d Deps) adAuthority(ctx context.Context, e *ldap.Entry) (*Counterpart, error) {
	soa := e.GetAttributeValue("msDS-ObjectSoa")
	var c *Counterpart
	if j, ok := joinOfEntry(e); ok && d.Graph != nil {
		var err error
		if c, err = d.fromAD(ctx, j, ad.SIDString(e.GetRawAttributeValue("objectSid")), soa); err != nil {
			return nil, fmt.Errorf("checking the source of authority of %s: %w", e.DN, err)
		}
	} else if strings.EqualFold(soa, "Cloud") {
		c = &Counterpart{SourceOfAuthority: "tenant", Source: "msDS-ObjectSoa"}
	}
	if c != nil && c.SourceOfAuthority != "forest" {
		return nil, fmt.Errorf("%s is managed in the tenant (%s says so), not the forest: change it in Entra instead", e.DN, c.Source)
	}
	return c, nil
}

// accountState is an ad-account-state action of the AD tool of k: a
// change to one account attribute.
func accountState(tool string, k adKind, action string) adExtra {
	var change func(e *ldap.Entry, in adIn) ([]ldap.Change, error)
	uac := func(disable bool) func(*ldap.Entry, adIn) ([]ldap.Change, error) {
		return func(e *ldap.Entry, _ adIn) ([]ldap.Change, error) {
			old := e.GetAttributeValue("userAccountControl")
			n, err := strconv.ParseUint(old, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%s: userAccountControl %q", e.DN, old)
			}
			n &^= 0x2 // ACCOUNTDISABLE, the only bit ever changed
			if disable {
				n |= 0x2
			}
			// Delete the value read, add the new one: one modify, so it fails
			// rather than clobbers when another writer got there first.
			return []ldap.Change{
				{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "userAccountControl", Vals: []string{old}}},
				{Operation: ldap.AddAttribute, Modification: ldap.PartialAttribute{Type: "userAccountControl", Vals: []string{strconv.FormatUint(n, 10)}}},
			}, nil
		}
	}
	set := func(attr, v string) []ldap.Change {
		return []ldap.Change{{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: attr, Vals: []string{v}}}}
	}
	switch action {
	case "disable", "enable":
		change = uac(action == "disable")
	case "unlock":
		change = func(*ldap.Entry, adIn) ([]ldap.Change, error) { return set("lockoutTime", "0"), nil }
	case "must_change":
		change = func(*ldap.Entry, adIn) ([]ldap.Change, error) { return set("pwdLastSet", "0"), nil }
	case "set_expiry":
		change = func(_ *ldap.Entry, in adIn) ([]ldap.Change, error) {
			v, err := fileTime(in.Expires)
			return set("accountExpires", v), err
		}
	}
	return adExtra{Action{Name: action, Capabilities: []string{"ad-account-state"}}, func(d Deps, ctx context.Context, in adIn) (map[string]any, error) {
		return d.adWrite(ctx, adWrite{tool: tool, action: action, id: in.ID, class: k.class, in: in.writeIn,
			changes: func(e *ldap.Entry) ([]ldap.Change, error) { return change(e, in) }})
	}}
}

// resetPassword is ad_user reset_password (ad-passwords): a generated
// password set by replacing unicodePwd over the TLS session, with
// must-change unless turned off. The reply is the one place it appears.
var resetPassword = adExtra{Action{Name: "reset_password", Capabilities: []string{"ad-passwords"}}, func(d Deps, ctx context.Context, in adIn) (map[string]any, error) {
	var pw secret
	must := in.MustChange == nil || *in.MustChange
	out, err := d.adWrite(ctx, adWrite{tool: "ad_user", action: "reset_password", id: in.ID, class: adUsers.class, in: in.writeIn,
		confirm: true, attrs: []string{"displayName"},
		changes: func(e *ldap.Entry) ([]ldap.Change, error) {
			pw = newPassword(0, e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("displayName"))
			// unicodePwd is the password in quotes, as UTF-16LE; generated passwords are ASCII.
			var v []byte
			for _, c := range `"` + string(pw) + `"` {
				v = append(v, byte(c), 0)
			}
			ch := []ldap.Change{{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "unicodePwd", Vals: []string{string(v)}}}}
			if must {
				ch = append(ch, ldap.Change{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "pwdLastSet", Vals: []string{"0"}}})
			}
			return ch, nil
		}})
	if err != nil {
		return nil, err
	}
	out["password"], out["must_change"] = string(pw), must
	return out, nil
}}

// maxMembers caps the members of one membership write (ADR 0001).
const maxMembers = 20

// membership is ad_group add_members or remove_members
// (ad-group-membership): one permissive modify of the group's member, so
// adding a member already in or removing one already out succeeds. A
// protected member is refused, as a protected group is.
func (d Deps) membership(ctx context.Context, in adGroupIn) (map[string]any, error) {
	if n := len(in.Members); n == 0 || n > maxMembers {
		return nil, fmt.Errorf("%s takes 1 to %d members, got %d: call again for more", in.Action, maxMembers, n)
	}
	op := uint(ldap.AddAttribute)
	if in.Action == "remove_members" {
		op = ldap.DeleteAttribute
	}
	var dns []string
	// Members are checked inside the write, after its reason, and a refusal is audited.
	changes := func(*ldap.Entry) ([]ldap.Change, error) {
		for _, m := range in.Members {
			dn, err := d.AD.Resolve(ctx, m, adObjects.class)
			if err != nil {
				return nil, fmt.Errorf("member %w", err)
			}
			why, err := adProtected(d.AD, ctx, dn)
			if err != nil {
				return nil, fmt.Errorf("member %w", err)
			}
			if why != "" {
				return nil, fmt.Errorf("member %s: %w: %s", dn, ad.ErrProtected, why)
			}
			dns = append(dns, dn)
		}
		slices.Sort(dns)
		dns = slices.Compact(dns) // one value twice in a modify is an error, even permissive
		return []ldap.Change{{Operation: op, Modification: ldap.PartialAttribute{Type: "member", Vals: dns}}}, nil
	}
	out, err := d.adWrite(ctx, adWrite{tool: "ad_group", action: in.Action, id: in.ID, class: adGroups.class, in: in.writeIn,
		controls: []ldap.Control{ldap.NewControlString(ldap.ControlTypeMicrosoftPermissiveModify, true, "")},
		changes:  changes})
	if err != nil {
		return nil, err
	}
	out["members"] = dns
	return out, nil
}

// fileTime turns an RFC 3339 time, or never, into an accountExpires value.
func fileTime(s string) (string, error) {
	if strings.EqualFold(s, "never") {
		return "9223372036854775807", nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("expires %q: want an RFC 3339 time (2026-12-31T23:59:59Z) or never", s)
	}
	// 100 ns intervals since 1601-01-01.
	return strconv.FormatInt(t.Unix()*1e7+int64(t.Nanosecond()/100)+116444736000000000, 10), nil
}

// secret is a generated password: returned once, and never logged. It
// prints and marshals redacted, wherever it lands; the one reply that
// returns it converts it to a string.
type secret string

func (secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (secret) String() string               { return "[redacted]" }
func (secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Password classes: AD complexity wants three of the four; these have all.
var pwClasses = []string{"ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!#%+-.:=?@_~"}

// newPassword generates a password of n characters (at least 20), with
// every class, and containing neither a name in avoid (sAMAccountName,
// displayName) nor any three-or-more-character part of one, as AD
// complexity requires.
func newPassword(n int, avoid ...string) secret {
	all := strings.Join(pwClasses, "")
	for {
		b := make([]byte, max(n, 20))
		for i := range b {
			x, err := rand.Int(rand.Reader, big.NewInt(int64(len(all))))
			if err != nil {
				panic(err) // crypto/rand does not fail on supported platforms
			}
			b[i] = all[x.Int64()]
		}
		if pw := string(b); complexEnough(pw, avoid) {
			return secret(pw)
		}
	}
}

// complexEnough reports whether pw has every class and none of the
// names in avoid, or their parts, in it.
func complexEnough(pw string, avoid []string) bool {
	for _, c := range pwClasses {
		if !strings.ContainsAny(pw, c) {
			return false
		}
	}
	low := strings.ToLower(pw)
	for _, name := range avoid {
		parts := append(strings.FieldsFunc(name, func(r rune) bool { return strings.ContainsRune(",.-_# \t", r) }), name)
		for _, p := range parts {
			if len(p) >= 3 && strings.Contains(low, strings.ToLower(p)) {
				return false
			}
		}
	}
	return true
}
