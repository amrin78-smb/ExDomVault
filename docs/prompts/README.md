# Claude Code prompts

Run one milestone per Claude Code session, from the repo root, in order:

```bash
claude "$(cat docs/prompts/01-repository-foundation.md)"
```

or paste the file contents into an open session. `CLAUDE.md` loads automatically and carries the persistent rules; each milestone prompt points Claude at `docs/progress.md` so state carries across sessions.

| File                        | Purpose                                                   |
| --------------------------- | --------------------------------------------------------- |
| `00-master-build-prompt.md` | Full original build prompt (reference for all milestones) |
| `01`–`11`                   | Per-milestone kickoff prompts                             |

Milestone 6 is a hard security gate: active network checks stay disabled until its scope-validator tests pass.
