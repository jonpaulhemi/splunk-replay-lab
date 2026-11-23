# splunk-replay-lab

Splunk app `replay_lab`: replays security datasets with current timestamps so ES detections fire. One shared engine, one pack folder per dataset (`datasets/<name>/`). Design decisions: `docs/DESIGN.md`. Spec: issue #1; tickets are its sub-issues.

- This repo is public. Never commit lab host names, IP addresses, domains, credentials or lab run notes. Use `example.com` hosts and documentation IP ranges (192.0.2.0/24) in examples. Run `python3 tools/scrub_check.py` before every push; it reads its deny-list from outside the repo.
- Python runs on Splunk's bundled 3.9 to 3.13, standard library only.
- Datasets are never committed; only the code and config that replay them.

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root, created lazily. See `docs/agents/domain.md`.
