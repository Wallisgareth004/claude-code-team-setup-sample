#!/bin/sh
# Point git at this repo's hooks (once per clone). Needs gitleaks on PATH.
set -e
git config core.hooksPath .githooks
command -v gitleaks >/dev/null 2>&1 || echo "Note: install gitleaks (brew install gitleaks); until then every commit is refused."
echo "Hooks enabled: .githooks/pre-commit runs a gitleaks scan on staged changes."
