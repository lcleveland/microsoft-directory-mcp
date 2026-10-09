package tools

import (
	"context"
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
	Name    string
	Perms   []string // Entra application permissions, any of
	Licence string   // P1, P2 or Intune
	ADProbe string   // an ad.ReadProbes name
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
// reasons. A tool whose side or group is off has neither.
func (d Deps) visibility(t Tool) (visible []string, hidden []Hidden) {
	if !d.sideOn(t.side()) || !d.Config.GroupOn(t.Group) {
		return nil, nil
	}
	for _, a := range t.Actions {
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
		if p.Roles != nil && len(a.Perms) > 0 && !slices.ContainsFunc(a.Perms, func(r string) bool { return slices.Contains(p.Roles, r) }) {
			return "missing permission: needs one of " + strings.Join(a.Perms, ", ")
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

// addActionTool registers def with its action enum cut to visible, and
// refuses any other action if it is called anyway.
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
	def.InputSchema = schema
	mcp.AddTool(s, def, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		if !slices.Contains(visible, in.action()) {
			var zero Out
			_, hidden := d.visibility(t)
			for _, x := range hidden {
				if x.Action == in.action() {
					return nil, zero, fmt.Errorf("%s %s is hidden: %s", t.Name, x.Action, x.Reason)
				}
			}
			return nil, zero, fmt.Errorf("action %q is not available on %s (available: %s)", in.action(), t.Name, strings.Join(visible, ", "))
		}
		return h(ctx, req, in)
	})
}

// Visibility is what the *_status tools report about one side.
type Visibility struct {
	EnabledGroups  []string            `json:"enabled_groups"`
	VisibleActions map[string][]string `json:"visible_actions"`
	HiddenActions  []Hidden            `json:"hidden_actions"`
}

func (d Deps) report(side string) Visibility {
	v := Visibility{VisibleActions: map[string][]string{}, HiddenActions: []Hidden{}}
	for _, g := range config.Groups {
		if d.Config.GroupOn(g) {
			v.EnabledGroups = append(v.EnabledGroups, g)
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
