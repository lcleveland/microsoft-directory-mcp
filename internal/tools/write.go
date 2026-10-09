package tools

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
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
	Confirm string `json:"confirm,omitempty" jsonschema:"writes, reset_password, delete, retire, wipe: the target's name exactly (an AD object's sAMAccountName, an Entra user's userPrincipalName, an Entra group's or device's displayName, an Intune device's deviceName), to confirm it is the one you mean"`
}

var errReason = errors.New("reason is required for writes: say why, it is recorded in the audit log")

// audited is a write error the rails have logged already; any other error
// of a write is logged as refused where every tool call passes (addActionTool).
type audited struct{ error }

func (e audited) Unwrap() error { return e.error }

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
	{"modify", "distinguishedName", "ad-delete", "ad_object restore"},
	{"add", "", "ad-objects", "ad_user, ad_group or ad_computer create"},
	{"delete", "", "ad-delete", "ad_object delete"},
	{"rename", "", "ad-objects", "ad_object rename or move"},
}

// adObjectAttrs is the ad-objects allowlist: by object class, the
// attributes ad_object edit, create and ad_api may set. Descriptive ones
// only: nothing that grants access, delegates, or changes how anyone signs in.
var adObjectAttrs = map[string][]string{
	"user": {"description", "displayName", "givenName", "sn", "initials", "title", "department", "company", "manager",
		"physicalDeliveryOfficeName", "telephoneNumber", "mobile", "streetAddress", "l", "st", "postalCode",
		"employeeID", "employeeNumber", "info"},
	"group":    {"description", "displayName", "info"},
	"computer": {"description", "location"},
}

func init() { adObjectAttrs["inetorgperson"] = adObjectAttrs["user"] } // a user too; keys are lower case

// adEditable is the class filter of the objects ad_object writes.
const adEditable = "(|(objectClass=user)(objectClass=group))"

// classifyAD maps one AD write (op: modify, add, delete or rename; attr
// for a modify) on an object of class (its most specific objectClass) to
// the capability that allows it. raw is a write of the client's own
// attributes (ad_api, ad_object edit), where a write that a first-class
// action makes is refused and pointed to that action.
func classifyAD(op, attr, class string, raw bool) (string, error) {
	for _, o := range adOps {
		if o.op == op && strings.EqualFold(o.attr, attr) {
			if raw {
				return "", fmt.Errorf("%s %s: call %s instead (the %s capability)", op, attr, o.action, o.capability)
			}
			return o.capability, nil
		}
	}
	if raw && op == "modify" && slices.ContainsFunc(adObjectAttrs[strings.ToLower(class)], func(a string) bool { return strings.EqualFold(a, attr) }) {
		return "ad-objects", nil
	}
	return "", fmt.Errorf("%s %s on %s is not a write this server makes", op, attr, cmp.Or(class, "this object"))
}

// adWrite is one AD write: an object, by id, and what is done to it: a
// modify (changes), a delete (del), or a rename or move (moveTo).
type adWrite struct {
	tool, action string
	id, class    string // the target, resolved as reads resolve it
	in           writeIn
	raw          bool     // the client's own attributes: classified as raw
	confirm      bool     // in.Confirm must name the target
	attrs        []string // read before the write, for changes
	changes      func(*ldap.Entry) ([]ldap.Change, error)
	controls     []ldap.Control
	del          bool
	moveTo       func(*ldap.Entry) (rdn, parent string, err error)
}

// adModify, adAdd and adProtected are the transport's; seams for tests.
var (
	adModify    = (*ad.Client).Modify
	adAdd       = (*ad.Client).Add
	adProtected = (*ad.Client).Protected
	adReaches   = (*ad.Client).Reaches
	adGet       = (*ad.Client).Get
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
	tgt, err := adModify(d.AD, ctx, dn, w.class, w.attrs, func(e *ldap.Entry) (any, error) {
		if name := cmp.Or(e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("name")); w.confirm && strings.TrimSpace(w.in.Confirm) != name {
			return nil, fmt.Errorf("confirm must be the target's name exactly: %s is %q. Check it is the object you mean, then retry", e.DN, name)
		}
		var (
			req any
			ops [][2]string // op, attribute: what is classified
		)
		switch {
		case w.del:
			req, ops = ldap.NewDelRequest(e.DN, nil), [][2]string{{"delete", ""}}
		case w.moveTo != nil:
			rdn, parent, err := w.moveTo(e)
			if err != nil {
				return nil, err
			}
			req, ops = ldap.NewModifyDNRequest(e.DN, rdn, true, parent), [][2]string{{"rename", ""}}
		default:
			changes, err := w.changes(e)
			if err != nil {
				return nil, err
			}
			req = &ldap.ModifyRequest{DN: e.DN, Changes: changes, Controls: w.controls}
			for _, ch := range changes {
				ops = append(ops, [2]string{"modify", ch.Modification.Type})
			}
		}
		var caps, names []string
		cls := append([]string{""}, e.GetAttributeValues("objectClass")...)
		for _, o := range ops {
			c, err := classifyAD(o[0], o[1], cls[len(cls)-1], w.raw)
			if err != nil {
				return nil, err
			}
			// A reset's must-change rides on its password write, under ad-passwords.
			if strings.EqualFold(o[1], "pwdLastSet") && slices.ContainsFunc(ops, func(x [2]string) bool { return strings.EqualFold(x[1], "unicodePwd") }) {
				c = "ad-passwords"
			}
			if !d.Config.Capabilities[c] {
				return nil, fmt.Errorf("%s needs the %s capability, which the operator has not enabled", cmp.Or(o[1], o[0]), c)
			}
			caps = append(caps, c)
			if o[1] != "" {
				names = append(names, o[1])
			}
		}
		if cp, err = d.adAuthority(ctx, e); err != nil {
			return nil, err
		}
		slices.Sort(caps)
		slices.Sort(names)
		// Attribute names only: values (passwords among them) are never logged.
		audit = append(audit, "capability", strings.Join(slices.Compact(caps), ","), "attributes", slices.Compact(names))
		return req, nil
	}, func() {
		// Logged before sending too, so a write cut off mid-call still has a record.
		d.log().Info("ad write", append(audit, "outcome", "sending")...)
		sent = true
	})
	audit = append(audit, "dc", tgt.DC, "fallback", tgt.Fallback)
	if err != nil {
		outcome := "failed"
		if !sent {
			outcome = "not sent"
		}
		d.log().Warn("ad write", append(audit, "outcome", outcome, "error", err.Error())...)
		return nil, audited{err}
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

// swap replaces the single value old of attr, as read, with to: it deletes
// old and adds to in one modify, so it fails rather than clobbers when
// another writer got there first. An empty old or new is no value.
func swap(attr, old, to string) []ldap.Change {
	var ch []ldap.Change
	if old != "" {
		ch = append(ch, ldap.Change{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: attr, Vals: []string{old}}})
	}
	if to != "" {
		ch = append(ch, ldap.Change{Operation: ldap.AddAttribute, Modification: ldap.PartialAttribute{Type: attr, Vals: []string{to}}})
	}
	return ch
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
			return swap("userAccountControl", old, strconv.FormatUint(n, 10)), nil
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
	return adExtra{Action: Action{Name: action, Capabilities: []string{"ad-account-state"}}, run: func(d Deps, ctx context.Context, in adIn) (map[string]any, error) {
		return d.adWrite(ctx, adWrite{tool: tool, action: action, id: in.ID, class: k.class, in: in.writeIn,
			changes: func(e *ldap.Entry) ([]ldap.Change, error) { return change(e, in) }})
	}}
}

// resetPassword is ad_user reset_password (ad-passwords): a generated
// password set by replacing unicodePwd over the TLS session, with
// must-change unless turned off. The reply is the one place it appears.
var resetPassword = adExtra{Action: Action{Name: "reset_password", Capabilities: []string{"ad-passwords"}}, run: func(d Deps, ctx context.Context, in adIn) (map[string]any, error) {
	var pw secret
	must := in.MustChange == nil || *in.MustChange
	out, err := d.adWrite(ctx, adWrite{tool: "ad_user", action: "reset_password", id: in.ID, class: adUsers.class, in: in.writeIn,
		confirm: true, attrs: []string{"displayName"},
		changes: func(e *ldap.Entry) ([]ldap.Change, error) {
			pw = newPassword(0, e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("displayName"))
			ch := []ldap.Change{{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "unicodePwd", Vals: []string{unicodePwd(pw)}}}}
			if must {
				ch = append(ch, ldap.Change{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "pwdLastSet", Vals: []string{"0"}}})
			}
			return ch, nil
		}})
	if err != nil {
		return nil, lostReset(err)
	}
	out["password"], out["must_change"] = string(pw), must
	return out, nil
}}

// lostReset is err from a password reset, saying so when the reply may
// have been lost after the reset was sent (a network error or timeout,
// not an answer): the password may then already be set.
func lostReset(err error) error {
	var ne net.Error
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) || errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w; if the reset was sent before the reply was lost, the password is already set to one nobody has: reset again rather than assume nothing changed", err)
	}
	return err
}

// unicodePwd is the value that sets pw: the password in quotes, as
// UTF-16LE; generated passwords are ASCII.
func unicodePwd(pw secret) string {
	var v []byte
	for _, c := range `"` + string(pw) + `"` {
		v = append(v, byte(c), 0)
	}
	return string(v)
}

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

// allowed refuses an attribute that allow, the allowlist for class, lacks.
func allowed(allow []string, class, attr string) error {
	if !slices.ContainsFunc(allow, func(a string) bool { return strings.EqualFold(a, attr) }) {
		return fmt.Errorf("%s is not an attribute this server sets on a %s; it sets %s", attr, class, strings.Join(allow, ", "))
	}
	return nil
}

// create is the create action (ad-objects) of the AD tool of class (user,
// computer or group): one object named name under parent, its
// sAMAccountName sam or name (a computer's ending in $), with allowlisted
// attributes, in one add. A user gets a generated password, returned once,
// must change it, and is enabled; a computer gets one nobody learns (a
// join to it resets it); a group gets groupType. A PSO (ad-password-policy)
// has no sAMAccountName, and every one of its settings.
func (d Deps) create(ctx context.Context, tool, class string, in adIn, groupType string) (map[string]any, error) {
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return nil, errReason
	}
	if in.Parent == "" || in.Name == "" {
		return nil, errors.New("create needs parent (the DN of an OU or container) and name")
	}
	if in.UPN != "" && class != "user" {
		return nil, errors.New("upn is for users")
	}
	dn := "CN=" + ldap.EscapeDN(in.Name) + "," + in.Parent
	sam := cmp.Or(in.Sam, in.Name)
	capability, allow := "ad-objects", adObjectAttrs[class]
	audit := []any{"tool", tool, "action", "create", "target", dn, "reason", reason}
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{class})
	var pw secret
	switch class {
	case "user":
		pw = newPassword(0, sam, in.Name, in.Attributes["displayName"])
		req.Attribute("sAMAccountName", []string{sam})
		if in.UPN != "" {
			req.Attribute("userPrincipalName", []string{in.UPN})
		}
		// Enabled (NORMAL_ACCOUNT), with the password set in the same add, which must change at next logon.
		req.Attribute("unicodePwd", []string{unicodePwd(pw)})
		req.Attribute("userAccountControl", []string{"512"})
		req.Attribute("pwdLastSet", []string{"0"})
	case "computer":
		sam = strings.TrimSuffix(sam, "$") + "$"
		req.Attribute("sAMAccountName", []string{sam})
		// WORKSTATION_TRUST_ACCOUNT, with a password rather than PASSWD_NOTREQD.
		req.Attribute("unicodePwd", []string{unicodePwd(newPassword(0, sam))})
		req.Attribute("userAccountControl", []string{"4096"})
	case "group":
		req.Attribute("sAMAccountName", []string{sam})
		req.Attribute("groupType", []string{groupType})
	case psoClass:
		capability, allow = "ad-password-policy", psoSettings
		set := func(a string) bool {
			return slices.ContainsFunc(slices.Collect(maps.Keys(in.Attributes)), func(k string) bool { return strings.EqualFold(k, a) && in.Attributes[k] != "" })
		}
		if missing := slices.DeleteFunc(slices.Clone(psoSettings), set); len(missing) > 0 {
			return nil, fmt.Errorf("create needs every PSO setting in attributes; missing %s", strings.Join(missing, ", "))
		}
	}
	keys := slices.Sorted(maps.Keys(in.Attributes))
	for _, k := range keys {
		if err := allowed(allow, class, k); err != nil {
			d.log().Warn("ad write", append(audit, "outcome", "not sent", "error", err.Error())...)
			return nil, audited{err}
		}
		if v := in.Attributes[k]; v != "" {
			req.Attribute(k, []string{v})
		}
	}
	var names []string
	for _, a := range req.Attributes {
		names = append(names, a.Type)
	}
	// Attribute names only: values (passwords among them) are never logged.
	audit = append(audit, "capability", capability, "attributes", names)
	d.log().Info("ad write", append(audit, "outcome", "sending")...)
	tgt, err := adAdd(d.AD, ctx, req)
	audit = append(audit, "dc", tgt.DC, "fallback", tgt.Fallback)
	if err != nil {
		d.log().Warn("ad write", append(audit, "outcome", "failed", "error", err.Error())...)
		return nil, audited{err}
	}
	d.log().Info("ad write", append(audit, "outcome", "ok")...)
	out := obj(tgt)
	out["dn"], out["action"] = dn, "create"
	if class != psoClass {
		out["sAMAccountName"] = sam
	}
	if class == "user" {
		out["password"], out["must_change"] = string(pw), true
	}
	return out, nil
}

// groupType is the groupType of a new group: scope global, domain_local
// or universal, a security group unless distribution.
func groupType(scope string, distribution bool) (string, error) {
	t, ok := map[string]uint32{"": 0x2, "global": 0x2, "domain_local": 0x4, "universal": 0x8}[scope]
	if !ok {
		return "", fmt.Errorf("group_scope %q: want global, domain_local or universal", scope)
	}
	if !distribution {
		t |= 0x80000000 // SECURITY_ENABLED
	}
	return strconv.Itoa(int(int32(t))), nil
}

// edit is ad_object edit (ad-objects): allowlisted attributes of one
// user, group or computer replaced, an empty value clearing one.
func (d Deps) edit(ctx context.Context, in adIn) (map[string]any, error) {
	changes, err := replaces(in.Attributes)
	if err != nil {
		return nil, err
	}
	return d.adWrite(ctx, adWrite{tool: "ad_object", action: "edit", id: in.ID, class: adEditable, in: in.writeIn, raw: true,
		changes: func(*ldap.Entry) ([]ldap.Change, error) { return changes, nil }})
}

// replaces replaces each attribute of attrs with its value, an empty one
// clearing it, for edit.
func replaces(attrs map[string]string) ([]ldap.Change, error) {
	if len(attrs) == 0 {
		return nil, errors.New("edit needs attributes")
	}
	var changes []ldap.Change
	for _, k := range slices.Sorted(maps.Keys(attrs)) {
		var vals []string
		if v := attrs[k]; v != "" {
			vals = []string{v}
		}
		changes = append(changes, ldap.Change{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: k, Vals: vals}})
	}
	return changes, nil
}

// moveOrRename is ad_object rename (a new name, same parent) or move (a
// new parent in the same domain), ad-objects. Connect Sync's OU filter
// can't be read, so a move of an object with a counterpart warns.
func (d Deps) moveOrRename(ctx context.Context, in adIn) (map[string]any, error) {
	moved, dn := false, ""
	out, err := d.adWrite(ctx, adWrite{tool: "ad_object", action: in.Action, id: in.ID, class: adEditable, in: in.writeIn,
		moveTo: func(e *ldap.Entry) (string, string, error) {
			p, err := ldap.ParseDN(e.DN)
			if err != nil {
				return "", "", err
			}
			rdn := p.RDNs[0].Attributes[0]
			if in.Action == "rename" {
				if in.Name == "" {
					return "", "", errors.New("rename needs name")
				}
				r := rdn.Type + "=" + ldap.EscapeDN(in.Name)
				dn = r + "," + parentOf(e.DN)
				return r, "", nil
			}
			to, err := ldap.ParseDN(in.Parent)
			if err != nil || in.Parent == "" {
				return "", "", fmt.Errorf("move needs parent, the DN of an OU or container of the same domain: %q", in.Parent)
			}
			moved = !to.EqualFold(&ldap.DN{RDNs: p.RDNs[1:]})
			r := rdn.Type + "=" + ldap.EscapeDN(rdn.Value)
			dn = r + "," + in.Parent
			return r, in.Parent, nil
		}})
	if err != nil {
		return nil, err
	}
	out["dn"] = dn
	if moved && out["sync"] != nil {
		out["warning"] = "its parent OU changed, and this server can't read Connect Sync's OU filter: if the new OU is " +
			"out of sync scope, its Entra counterpart is soft-deleted on the next sync cycle"
	}
	return out, nil
}

// parentOf is dn without its first RDN, as written.
func parentOf(dn string) string {
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case ',':
			return dn[i+1:]
		}
	}
	return ""
}

// deleteObject is ad_object delete (ad-delete): one leaf object, with
// confirm. Never a tree delete.
func (d Deps) deleteObject(ctx context.Context, in adIn) (map[string]any, error) {
	out, err := d.adWrite(ctx, adWrite{tool: "ad_object", action: "delete", id: in.ID, class: adEditable, in: in.writeIn,
		confirm: true, del: true})
	if err != nil {
		return nil, err
	}
	out["warning"] = "a delete reaches Entra through sync: if the object is in sync scope, its Entra counterpart is " +
		"deleted on the next sync cycle. ad_object restore brings it back here, with search_deleted's dn"
	return out, nil
}

// restore is ad_object restore (ad-delete): a deleted object, by the dn
// search_deleted gives, reanimated under its lastKnownParent (or parent)
// with its old name. With the Recycle Bin on it regains its group
// memberships, so a former protected-group member (adminCount) is refused.
func (d Deps) restore(ctx context.Context, in adIn) (map[string]any, error) {
	var dn string
	out, err := d.adWrite(ctx, adWrite{tool: "ad_object", action: "restore", id: in.ID, class: adDeleted.class, in: in.writeIn,
		attrs: []string{"lastKnownParent", "msDS-LastKnownRDN"}, controls: []ldap.Control{ldap.NewControlMicrosoftShowDeleted()},
		changes: func(e *ldap.Entry) ([]ldap.Change, error) {
			p, err := ldap.ParseDN(e.DN)
			if err != nil {
				return nil, err
			}
			rdn := p.RDNs[0].Attributes[0]
			// A deleted object's name is its old one, then a newline and DEL:<objectGUID>.
			name, _, _ := strings.Cut(cmp.Or(e.GetAttributeValue("msDS-LastKnownRDN"), rdn.Value), "\n")
			parent := cmp.Or(in.Parent, e.GetAttributeValue("lastKnownParent"))
			if parent == "" {
				return nil, fmt.Errorf("%s has no lastKnownParent: pass parent", e.DN)
			}
			dn = rdn.Type + "=" + ldap.EscapeDN(name) + "," + parent
			return []ldap.Change{
				{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "isDeleted"}},
				{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "distinguishedName", Vals: []string{dn}}},
			}, nil
		}})
	if err != nil {
		return nil, err
	}
	out["restored_as"] = dn
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
