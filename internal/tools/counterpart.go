package tools

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/lcleveland/microsoft-directory-mcp/internal/ad"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// A join is a kind of object both sides hold, linked by SID: AD objectSid
// is Entra onPremisesSecurityIdentifier.
type join struct {
	ad    adKind
	entra entraKind
	// behavior: onPremisesSyncBehavior covers it (users and groups, not devices).
	behavior bool
}

var (
	joinUser   = join{adUsers, entraUsers, true}
	joinGroup  = join{adGroups, entraGroups, true}
	joinDevice = join{adComputers, entraDevices, false}
)

// joinOf is the join of an AD class filter.
func joinOf(class string) (join, bool) {
	for _, j := range []join{joinUser, joinGroup, joinDevice} {
		if j.ad.class == class {
			return j, true
		}
	}
	return join{}, false
}

// counterpartDoc is said of every get carrying the counterpart block.
const counterpartDoc = " With both sides configured, a get without fields carries counterpart: the object's counterpart on " +
	"the other side (matched by SID) and the source of authority, forest or tenant, with the source that said so."

// Counterpart is an object's counterpart on the other side, if any, and
// which side is its source of authority (forest or tenant).
type Counterpart struct {
	ID                string `json:"id,omitempty"` // the Entra object id, or the AD DN
	SourceOfAuthority string `json:"source_of_authority"`
	Source            string `json:"source"` // what said so
}

// adBySID reads msDS-ObjectSoa of the AD object of class with sid; a seam
// for tests.
var adBySID = func(ctx context.Context, d Deps, sid, class string) (*ldap.Entry, error) {
	return d.AD.Get(ctx, sid, class, []string{"msDS-ObjectSoa"})
}

// fromAD finds the Entra counterpart of an AD object by its SID; soa is
// its msDS-ObjectSoa.
func (d Deps) fromAD(ctx context.Context, j join, sid, soa string) (*Counterpart, error) {
	p, err := d.Graph.List(ctx, j.entra.path, graph.Params{Filter: "onPremisesSecurityIdentifier eq '" + strings.ReplaceAll(sid, "'", "''") + "'",
		Fields: []string{"id", "onPremisesSyncEnabled"}}, "")
	if err != nil {
		return nil, err
	}
	c := &Counterpart{SourceOfAuthority: "forest", Source: "no Entra object has its SID"}
	// ponytail: a SID is unique per tenant; the first match is taken without checking for a second.
	if len(p.Results) > 0 {
		c.ID, _ = p.Results[0]["id"].(string)
	}
	if strings.EqualFold(soa, "Cloud") {
		c.SourceOfAuthority, c.Source = "tenant", "msDS-ObjectSoa"
		return c, nil
	}
	if c.ID == "" {
		return c, nil
	}
	return d.authority(ctx, j, c, c.ID, p.Results[0]["onPremisesSyncEnabled"])
}

// fromEntra finds the AD counterpart of an Entra object (with id,
// onPremisesSecurityIdentifier and onPremisesSyncEnabled) by its SID.
func (d Deps) fromEntra(ctx context.Context, j join, obj map[string]any) (*Counterpart, error) {
	id, _ := obj["id"].(string)
	sid, _ := obj["onPremisesSecurityIdentifier"].(string)
	if sid == "" {
		return &Counterpart{SourceOfAuthority: "tenant", Source: "cloud-only: no onPremisesSecurityIdentifier"}, nil
	}
	c := &Counterpart{}
	e, err := adBySID(ctx, d, sid, j.ad.class)
	switch {
	case errors.Is(err, ad.ErrNoMatch):
	case err != nil:
		return nil, err
	default:
		c.ID = e.DN
		if strings.EqualFold(e.GetAttributeValue("msDS-ObjectSoa"), "Cloud") {
			c.SourceOfAuthority, c.Source = "tenant", "msDS-ObjectSoa"
			return c, nil
		}
	}
	return d.authority(ctx, j, c, id, obj["onPremisesSyncEnabled"])
}

// authority sets c's source of authority from the Entra object id:
// onPremisesSyncBehavior.isCloudManaged where Graph answers it, else
// onPremisesSyncEnabled (true: the forest). Other Graph errors are errors,
// so a write checking authority fails closed.
func (d Deps) authority(ctx context.Context, j join, c *Counterpart, id string, syncEnabled any) (*Counterpart, error) {
	if j.behavior {
		var b struct {
			IsCloudManaged *bool `json:"isCloudManaged"`
		}
		err := d.Graph.Object(ctx, j.entra.path+"/"+url.PathEscape(id)+"/onPremisesSyncBehavior", graph.Params{Fields: []string{"isCloudManaged"}}, &b)
		var ae *graph.APIError
		switch {
		case err == nil && b.IsCloudManaged != nil:
			c.SourceOfAuthority, c.Source = "forest", "onPremisesSyncBehavior.isCloudManaged"
			if *b.IsCloudManaged {
				c.SourceOfAuthority = "tenant"
			}
			return c, nil
		// 403: no grant; 404, or 400 for a segment v1.0 doesn't know: no such path.
		case err != nil && !(errors.As(err, &ae) && (ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound || ae.Status == http.StatusBadRequest)):
			return nil, err
		}
	}
	c.SourceOfAuthority, c.Source = "tenant", "onPremisesSyncEnabled"
	if syncEnabled == true {
		c.SourceOfAuthority = "forest"
	}
	return c, nil
}

// addCounterpart adds the counterpart block to a get when both sides are
// configured; a join that fails says so in the block.
func (d Deps) addCounterpart(out map[string]any, resolve func() (*Counterpart, error)) {
	if d.AD == nil || d.Graph == nil {
		return
	}
	c, err := resolve()
	if err != nil {
		out["counterpart"] = map[string]string{"error": err.Error()}
		return
	}
	out["counterpart"] = c
}

// entraGetJoined gets one object of j's Entra kind with its counterpart.
func (d Deps) entraGetJoined(ctx context.Context, j join, in entraIn) (map[string]any, error) {
	out, err := d.entraObject(ctx, j.entra, in, j.entra.get)
	if err == nil && len(in.Fields) == 0 {
		d.addCounterpart(out, func() (*Counterpart, error) { return d.fromEntra(ctx, j, out) })
	}
	return out, err
}
