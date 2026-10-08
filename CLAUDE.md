# CLAUDE.md

## Agent skills

### Issue tracker

Issues live in GitHub Issues (lcleveland/microsoft-directory-mcp), managed via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical labels: needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Code work

Invoke the `ponytail:ponytail` skill before any code work (writing, fixing, refactoring, reviewing) and follow its ladder.

## Decisions

When a decision is split (options genuinely close), convene a council before recommending: spawn one subagent per option in parallel, each arguing for its option, then judge between the cases and present the recommendation as a chooser (AskUserQuestion).

## Directory privacy

This repo and its issues are public. Never write identifying details of the operator's directories into them: forest/domain names, domain controller hostnames, OU layout, tenant ID or domain, app registration IDs, licence SKUs, or user/group/device data from live calls. Keep such facts in `~/.config/microsoft-directory-mcp/directory-notes.md` (outside the repo). Docs, tests and fixtures use placeholders (e.g. `example.com`, `corp.example.com`, made-up GUIDs). Generic AD/Graph behaviour learned from live calls is fine to record.
