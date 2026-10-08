---
name: pr-description
description: >-
  Write a pull-request description from the current branch's changes: what changed, why,
  how to test it and what to watch for. Read-only: it reads the diff and the log, never
  edits files or pushes. Triggers: "write the PR description", "describe this branch",
  "what goes in the PR".
allowed-tools: Read, Grep, Glob, Bash(git diff:*), Bash(git log:*), Bash(git status)
---

# pr-description

1. `git status` and `git log --oneline main..HEAD` to see the branch's commits.
2. `git diff main...HEAD --stat`, then read the changed files that matter.
3. Write the description in this shape, plain and short:

```
## What changed
<2-4 bullets, user-visible first>
## Why
<one or two sentences; link the issue if the commits name one>
## How to test
<the exact commands or clicks>
## Watch for
<migrations, config or env changes, anything risky; "nothing special" is fine>
```

Rules: describe only what the diff shows; never paste secrets or env values; don't push
or open the PR yourself. The person reviews it and opens the PR.
