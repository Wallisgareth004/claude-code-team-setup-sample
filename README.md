# Claude Code team setup: a sample

A small, working example of a safe Claude Code setup for a team repo: what Claude may read, what it must ask before running, and a secret scan on every commit. Copy the parts you want into your own repo.

It is the sample deliverable for an offer: "Claude Code setup for a small team".

## What's in it

| Path | What it does |
|---|---|
| `.claude/settings.json` | Permission rules. **Denied:** reading or editing `.env` files, `secrets/`, `~/.ssh`, `~/.aws`. **Ask first:** `git push`, `git reset --hard`, `git clean`, branch deletes, recursive deletes, `sudo`, `npm publish`. **Allowed without a prompt:** status, diff, log and the test command. Bypass-permissions mode is switched off. |
| `.claude/hooks/guard.py` | A second layer that runs before each tool call. It blocks the common ways secrets are reached (`Read`, `Grep`, `cat .env` or `cat .en?` in the shell), asks before risky commands even inside a chain (`npm test && git push`) or `bash -c "..."`, and **blocks force pushes**. It also keeps the pre-allowed commands read-only: `git diff`/`log` with `--output` and pytest with `--basetemp` or `-p` are denied. A command it can't parse asks rather than guesses. |
| `CLAUDE.md` | A template for the repo's instructions: commands, layout, conventions and the guard rails, in about 30 lines. |
| `.claude/skills/pr-description/` | An example project skill: it drafts a pull-request description from the branch diff, read-only. |
| `.githooks/pre-commit` | A [gitleaks](https://github.com/gitleaks/gitleaks) scan of the staged changes. It **fails closed**: with no gitleaks installed, no commit. |
| `tests/` | 34 tests that show each guard firing, and everyday work not being slowed down. |

## Use it
```sh
cp -R .claude CLAUDE.md /path/to/your/repo/      # then fill in CLAUDE.md
cp -R .githooks scripts /path/to/your/repo/
cd /path/to/your/repo && sh scripts/install-hooks.sh   # needs: brew install gitleaks
```
Claude Code picks up `.claude/settings.json` when a session starts in the repo.

## Run the tests
```sh
python3 -m unittest discover -s tests     # or: python3 -m pytest
```
Standard library only. The pre-commit tests build throwaway git repos in a temp folder and skip if gitleaks isn't installed. The fake token they use is generated at run time, so this repo never holds one.

## Limits (read these)
- The hook reads the **command text**. A script that opens a secret from inside itself is out of its sight; the permission rules and keeping secrets out of the repo are the real fix.
- Permission rules match file **reads and edits** (`Read(...)`, `Edit(...)`). Claude Code checks writes against `Edit(...)` rules, so there are no `Write(...)` rules here: they would look like protection and do nothing.
- The `python3 -m pytest` and `npm test` allow rules run the checked-out branch's own test code (`conftest.py`, `package.json` scripts) without a prompt. Review an outside contributor's branch before letting Claude run its tests.
- This is a guard rail for an honest assistant making mistakes, not a sandbox against a determined attacker.

## Licence
MIT. See `LICENSE`.
