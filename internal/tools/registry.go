package tools

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/microsoft-directory-mcp/internal/config"
	"github.com/lcleveland/microsoft-directory-mcp/internal/graph"
)

// Action is one action of a tool and what it needs to work. An action whose
// needs the startup probe found missing is hidden.
type Action struct {
	Name      string
	Perms     []string // Entra application permissions, any of
	AlsoPerms []string // and any of these too
	Licence   string   // P1, P2 or Intune
	ADProbe   string   // an ad.ReadProbes name
	// Capabilities make it a write, shown only when one of them is enabled.
	Capabilities []string
}

// capOn reports whether a's capability is enabled, or a is a read.
func (d Deps) capOn(a Action) bool {
	return len(a.Capabilities) == 0 || slices.ContainsFunc(a.Capabilities, func(c string) bool { return d.Config.Capabilities[c] })
}

// Tool is a roster entry. Its side is its name prefix (ad_ or entra_).
type Tool struct {
	Name    string
	Group   string
	Actions []Action
	// add registers the tool with only the visible actions.
	add func(s *mcp.Server, d Deps, t Tool, visible []string)
}

// roster lists every action-based tool, in roster order. Tool issues add
// theirs; ad_status and entra_status are registered separately.
var roster []Tool

func (t Tool) side() string { return strings.SplitN(t.Name, "_", 2)[0] }

// Hidden is an action the probe hid, and why.
type Hidden struct {
	Tool   string `json:"tool"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// sideOn reports whether side ("ad" or "entra") is configured.
func (d Deps) sideOn(side string) bool {
	if side == "ad" {
		return d.AD != nil
	}
	return d.Graph != nil
}

// visibility splits t's actions into visible names and hidden ones with
// reasons. A tool whose side or group is off has neither, nor has a write
// whose capability is off: it does not exist for the client.
func (d Deps) visibility(t Tool) (visible []string, hidden []Hidden) {
	if !d.sideOn(t.side()) || !d.Config.GroupOn(t.Group) {
		return nil, nil
	}
	for _, a := range t.Actions {
		if !d.capOn(a) {
			continue
		}
		if why := d.why(t, a); why != "" {
			hidden = append(hidden, Hidden{t.Name, a.Name, why})
		} else {
			visible = append(visible, a.Name)
		}
	}
	return visible, hidden
}

// why says why a is hidden, or "" when it is visible. Anything the probe
// could not decide shows.
func (d Deps) why(t Tool, a Action) string {
	if p := d.EntraProbe; p != nil && t.side() == "entra" {
		for _, perms := range [][]string{a.Perms, a.AlsoPerms} {
			if p.Roles != nil && len(perms) > 0 && !slices.ContainsFunc(perms, func(r string) bool { return slices.Contains(p.Roles, r) }) {
				return "missing permission: needs one of " + strings.Join(perms, ", ")
			}
		}
		if r, ok := p.Groups[t.Group]; ok && p.Roles == nil && len(a.Perms) > 0 && (r.State == graph.ReadPermission || r.State == graph.ReadLicence) {
			return fmt.Sprintf("%s read probe refused: %s (HTTP %d %s)", t.Group, r.State, r.Status, r.Code)
		}
		if a.Licence != "" && p.Licences[a.Licence] == graph.Absent {
			return "licence: needs " + a.Licence
		}
	}
	if p := d.ADProbe; p != nil && a.ADProbe != "" {
		if r, ok := p.Reads[a.ADProbe]; ok && r != "ok" {
			return "AD right: " + a.ADProbe + ": " + r
		}
	}
	return ""
}

// ActionParam is the action parameter every roster tool's input embeds.
type ActionParam struct {
	Action string `json:"action" jsonschema:"what to do; the tool description lists the actions"`
}

func (a ActionParam) action() string { return a.Action }

// writeAnnotations mark a tool with a visible write.
var writeAnnotations = &mcp.ToolAnnotations{DestructiveHint: new(true), OpenWorldHint: new(true)}

// addActionTool registers def with its action enum cut to visible, and
// refuses any other action if it is called anyway. A write parameter (its
// description starts "writes: " for every write, or "writes, a, b: " for
// actions a and b) is left out of the schema when none of its writes is
// visible; with a write visible the tool is annotated as one.
func addActionTool[In interface{ action() string }, Out any](s *mcp.Server, d Deps, t Tool, def *mcp.Tool, visible []string, h mcp.ToolHandlerFor[In, Out]) {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(t.Name + ": " + err.Error()) // static types: only a programming error lands here
	}
	enum := make([]any, len(visible))
	for i, v := range visible {
		enum[i] = v
	}
	schema.Properties["action"].Enum = enum
	var writes []string
	for _, a := range t.Actions {
		if len(a.Capabilities) > 0 && slices.Contains(visible, a.Name) {
			writes = append(writes, a.Name)
		}
	}
	for name, p := range schema.Properties {
		head, _, ok := strings.Cut(p.Description, ": ")
		serves, isWrite := strings.CutPrefix(head, "writes")
		if !ok || !isWrite {
			continue
		}
		used := len(writes) > 0
		if serves = strings.TrimPrefix(serves, ", "); serves != "" {
			used = slices.ContainsFunc(strings.Split(serves, ", "), func(a string) bool { return slices.Contains(writes, a) })
		}
		if !used {
			delete(schema.Properties, name)
		}
	}
	if len(writes) > 0 {
		ann := *writeAnnotations
		def.Annotations = &ann
	}
	def.InputSchema = schema
	mcp.AddTool(s, def, func(ctx context.Context, req *mcp.CallToolRequest, in In) (_ *mcp.CallToolResult, _ Out, err error) {
		defer func() {
			if err != nil && slices.ContainsFunc(t.Actions, func(a Action) bool { return a.Name == in.action() && len(a.Capabilities) > 0 }) &&
				!errors.As(err, new(audited)) {
				d.refused(t.Name, in.action(), in, err)
			}
		}()
		if err := d.refuse(t, visible, in.action()); err != nil {
			var zero Out
			return nil, zero, err
		}
		return h(ctx, req, in)
	})
}

// refused logs a write refused before the rails logged it: its target as
// given (id, dn or path) and reason, never other inputs.
func (d Deps) refused(tool, action string, in any, err error) {
	var f struct{ ID, DN, Path, UPN, Name, Reason string }
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, &f)
	side, _, _ := strings.Cut(tool, "_")
	d.log().Warn(side+" write", "tool", tool, "action", action, "target", cmp.Or(f.ID, f.DN, f.Path, f.UPN, f.Name),
		"reason", strings.TrimSpace(f.Reason), "outcome", "refused: "+err.Error())
}

// refuse says why action is not run on t, or nil when it is visible. The
// SDK's enum check refuses first; this holds should a call get past it.
func (d Deps) refuse(t Tool, visible []string, action string) error {
	if slices.Contains(visible, action) {
		return nil
	}
	for _, a := range t.Actions {
		if a.Name == action && !d.capOn(a) {
			return fmt.Errorf("%s %s is a write the operator has not enabled: it needs the %s capability (--capabilities)",
				t.Name, a.Name, strings.Join(a.Capabilities, " or "))
		}
	}
	_, hidden := d.visibility(t)
	for _, x := range hidden {
		if x.Action == action {
			return fmt.Errorf("%s %s is hidden: %s", t.Name, x.Action, x.Reason)
		}
	}
	return fmt.Errorf("action %q is not available on %s (available: %s)", action, t.Name, strings.Join(visible, ", "))
}

// Visibility is what the *_status tools report about one side.
type Visibility struct {
	EnabledGroups       []string            `json:"enabled_groups"`
	EnabledCapabilities []string            `json:"enabled_capabilities"`
	VisibleActions      map[string][]string `json:"visible_actions"`
	HiddenActions       []Hidden            `json:"hidden_actions"`
}

func (d Deps) report(side string) Visibility {
	v := Visibility{VisibleActions: map[string][]string{}, HiddenActions: []Hidden{}, EnabledCapabilities: []string{}}
	for _, g := range config.Groups {
		if d.Config.GroupOn(g) {
			v.EnabledGroups = append(v.EnabledGroups, g)
		}
	}
	for _, c := range config.Capabilities {
		if d.Config.Capabilities[c] && (side == "ad") == strings.HasPrefix(c, "ad-") {
			v.EnabledCapabilities = append(v.EnabledCapabilities, c)
		}
	}
	for _, t := range roster {
		if t.side() != side {
			continue
		}
		vis, hid := d.visibility(t)
		if len(vis) > 0 {
			v.VisibleActions[t.Name] = vis
		}
		v.HiddenActions = append(v.HiddenActions, hid...)
	}
	return v
}
