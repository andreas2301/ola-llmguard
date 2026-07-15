---
scope: repo
schema_version: 1
architect: true
osengineer_version: 0.4.0
project_classification: large
teams:
  - team_id: coding
    folder: null
    agents: [developer, reviewer]
    owns_paths:
      - "src/**"
    reads_paths:
      - "api/**"
      - "contracts/**"
      - "ansible/**"
      - "docs/**"
    escalates_to: [testing, infra, docs, security]
  - team_id: testing
    folder: tests/
    agents: [qa]
    owns_paths:
      - "**/test_*.py"
      - "tests/**"
      - "test/**"
      - "integration/**"
      - "e2e/**"
    reads_paths:
      - "internal/**"
      - "cmd/**"
      - "pkg/**"
      - "src/**"
      - "api/**"
      - "contracts/**"
    escalates_to: [coding]
  - team_id: docs
    folder: null
    agents: [tech-writer]
    owns_paths:
      - "**/*.schema.json"
      - "service-manifest.yml"
      - "message-contract*.yaml"
    reads_paths:
      - "**"
    escalates_to: [coding, infra, security]
  - team_id: security
    folder: null
    agents: [red-team-local, red-team-architect]
    owns_paths:
      - ".github/codeql/**"
      - "security/**"
      - ".secretscanignore"
      - ".base64scanignore"
    reads_paths:
      - "**"
    escalates_to: [coding, infra, docs]
phase_state_file: ./.osengineer/state.yml
---

# ola-llmguard — osEngineer repo manifest

This file is the architect/orchestrator for ola-llmguard. The frontmatter is
machine-parseable by osEngineer hooks (validated against
`specs/SCHEMAS/agents-md.schema.json`); the prose below is for humans.

## Teams

The frontmatter `teams:` list above was auto-detected from the repo layout
(Go modules, ansible/, *_test.go globs, docs/, .github/codeql). Edit it to
correct mistakes — `install.sh` re-runs are idempotent and never overwrite
this file once it exists. If you change the teams list, also re-run
`osengineer detect-teams .` to refresh the JSON cache at
`.osengineer/teams/<team>.json` that the pre-edit guard consumes.

## How osEngineer works in this repo

- **Phase state** lives in `.osengineer/state.yml`. Inspect with
  `osengineer state`. The state machine flows
  `idle → discuss → plan → execute → verify → accepted`.
- **Cross-team handoffs** live in `.osengineer/handoffs/HO-<n>-*.md`.
  Open one with `osengineer handoff open --from <a> --to <b> --slug <s>`.
- **Phase-aware enforcement** — during `discuss` and `plan`, edits are
  read-only outside `planning/` and `.osengineer/`.
- **owns_paths enforcement** — during `execute` with a `current_team`
  set, edits to a path outside that team's `owns_paths` are blocked.
- **Conventional Commits** — the `commit-msg` git hook enforces format.
- **Destructive bash** (`rm -rf`, `git push --force`, etc.) is blocked
  without an active 4-part plan in `.osengineer/current-plan.md`.
- **Override any rule** with `OSE_BYPASS=1` — logged to
  `.osengineer/bypass-log.jsonl`.

Run `osengineer explain hooks` for the full enforcement layer summary.
