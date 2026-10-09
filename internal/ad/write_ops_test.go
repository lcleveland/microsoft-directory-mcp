package ad

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// A delete, a move and an add are sent once on the PDC emulator; a
// protected target's delete is not.
func TestWriteKinds(t *testing.T) {
	f := newFakeDir()
	cases := seedProtected(f)
	c := f.client(srvConfig())
	ctx := context.Background()

	moved := "CN=plain,OU=Staff," + corpDN
	f.tree[strings.ToLower("OU=Staff,"+corpDN)] = map[string][]string{"objectClass": {"top", "organizationalUnit"}}
	if _, err := c.Modify(ctx, plain, userClass, nil, func(e *ldap.Entry) (any, error) {
		return ldap.NewModifyDNRequest(e.DN, "CN=plain", true, "OU=Staff,"+corpDN), nil
	}); err != nil {
		t.Fatal(err)
	}
	if f.tree[strings.ToLower(moved)] == nil || f.tree[strings.ToLower(plain)] != nil {
		t.Errorf("not moved: %q", f.modifies)
	}
	if _, err := c.Modify(ctx, moved, userClass, nil, func(e *ldap.Entry) (any, error) { return ldap.NewDelRequest(e.DN, nil), nil }); err != nil {
		t.Fatal(err)
	}
	if f.tree[strings.ToLower(moved)]["isDeleted"] == nil {
		t.Errorf("not deleted: %v", f.tree[strings.ToLower(moved)])
	}
	// A deleted object, which has no memberships to check, is written only by a restore.
	if _, err := c.Modify(ctx, moved, "(isDeleted=TRUE)", nil, describe); err == nil || !strings.Contains(err.Error(), "only ad_object restore") {
		t.Errorf("deleted, no show-deleted: %v", err)
	}
	if _, err := c.Modify(ctx, moved, "(isDeleted=TRUE)", nil, func(e *ldap.Entry) (any, error) {
		return &ldap.ModifyRequest{DN: e.DN, Controls: []ldap.Control{ldap.NewControlMicrosoftShowDeleted()}, Changes: []ldap.Change{
			{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "description", Vals: []string{"x"}}}}}, nil
	}); err != nil {
		t.Errorf("deleted pre-read: %v", err)
	}
	if _, err := c.Modify(ctx, cases["adminCount"], userClass, nil, func(e *ldap.Entry) (any, error) { return ldap.NewDelRequest(e.DN, nil), nil }); !errors.Is(err, ErrProtected) {
		t.Errorf("protected delete: %v", err)
	}

	// A move into another domain is refused before sending.
	if _, err := c.Modify(ctx, lonely, "(objectClass=group)", nil, func(e *ldap.Entry) (any, error) {
		return ldap.NewModifyDNRequest(e.DN, "CN=lonely", true, "CN=Users,"+childDN), nil
	}); err == nil || !strings.Contains(err.Error(), "cross-domain moves are never made") {
		t.Errorf("cross-domain move: %v", err)
	}

	add := ldap.NewAddRequest("CN=new,OU=Staff,"+corpDN, nil)
	add.Attribute("objectClass", []string{"user"})
	tgt, err := c.Add(ctx, add)
	if err != nil || tgt.DC != "dc2.corp.example.com:636" || f.tree[strings.ToLower(add.DN)] == nil {
		t.Errorf("add: %+v %v", tgt, err)
	}
	if _, err := c.Add(ctx, add); !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Errorf("add again: %v", err)
	}
	if want := []string{"dc2.corp.example.com " + plain, "dc2.corp.example.com " + moved, "dc2.corp.example.com " + moved, "dc2.corp.example.com " + add.DN}; !strings.EqualFold(strings.Join(f.modifies, "|"), strings.Join(want, "|")) {
		t.Errorf("sent %q", f.modifies)
	}
}
