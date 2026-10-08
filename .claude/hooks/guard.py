#!/usr/bin/env python3
"""Guard hook for Claude Code (PreToolUse). Two guards, one file:

1. Secret files are blocked: .env files, anything under secrets/ or ~/.ssh,
   private keys and cloud credentials, whether reached by Read, Edit, Write,
   Grep or a shell command such as `cat .env`.
2. Risky commands ask first: pushes, destructive git, recursive deletes,
   sudo, piping a download into a shell, publishing a package. A force push
   is denied outright.

Everything else passes untouched. A command the hook can't parse asks rather
than guesses. Standard library only; the tests in tests/test_guard.py show
each guard firing. Registered in .claude/settings.json.

This is a guard rail, not a sandbox: it reads the command text, so a script
that reads a secret inside itself is out of its sight. The permission rules
in settings.json are the first layer; this hook is the second.
"""

import json
import os
import re
import shlex
import sys

FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
SAFE_SUFFIXES = (".example", ".sample", ".template")
KEY_NAMES = re.compile(
    r"^(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$|\.(pem|key|p12|pfx)$", re.I
)
SEPARATORS = {";", "&&", "||", "|", "&", "\n"}
SHELLS = {"sh", "bash", "zsh"}


def is_secret(path):
    if not path or path.startswith("-"):
        return False
    p = os.path.normpath(os.path.expanduser(path))
    parts = p.replace("\\", "/").split("/")
    name = parts[-1]
    if name.endswith(SAFE_SUFFIXES):
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if "secrets" in parts[:-1] or name == "secrets":
        return True
    if ".ssh" in parts[:-1]:
        return True
    if len(parts) >= 2 and parts[-2] == ".aws" and name in ("credentials", "config"):
        return True
    return bool(KEY_NAMES.search(name))


SECRET_REASON = (
    "Blocked: {0} looks like a secret (an env file, key or credential). Secrets stay out of "
    "the AI's context. Ask the person to share the variable names only, or read env.example."
)


def segments(command):
    """[(tokens, piped_from_previous)] split on ; && || | &. Raises ValueError."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    out, cur, piped = [], [], False
    for tok in lex:
        if tok in SEPARATORS:
            if cur:
                out.append((cur, piped))
            cur, piped = [], tok == "|"
        else:
            cur.append(tok)
    if cur:
        out.append((cur, piped))
    return out


def risky(tokens, piped):
    """(decision, reason) for one simple command, or None."""
    while tokens and re.match(r"^\w+=", tokens[0]):  # FOO=bar cmd
        tokens = tokens[1:]
    if not tokens:
        return None
    cmd, args = os.path.basename(tokens[0]), tokens[1:]
    if piped and cmd in SHELLS:
        return "ask", "pipes downloaded text into a shell"
    if cmd == "sudo":
        return "ask", "runs a command as root"
    if cmd == "rm" and any(a.startswith("-") and re.search(r"[rR]", a) for a in args):
        return "ask", "deletes recursively"
    if cmd in ("npm", "pnpm", "yarn") and args[:1] == ["publish"]:
        return "ask", "publishes a package"
    if cmd == "twine" and args[:1] == ["upload"]:
        return "ask", "publishes a package"
    if cmd != "git" or not args:
        return None
    sub, rest = args[0], args[1:]
    if sub == "push":
        if any(a in ("--force", "-f") or a.startswith("--force=") for a in rest) or any(
            a.startswith("+") for a in rest
        ):
            return (
                "deny",
                "force-pushes, which rewrites shared history (do it by hand if you must)",
            )
        return "ask", "pushes to a shared remote"
    if sub == "reset" and "--hard" in rest:
        return "ask", "throws away uncommitted work (reset --hard)"
    if sub == "clean" and any(a.startswith("-") and "f" in a for a in rest):
        return "ask", "deletes untracked files (git clean -f)"
    if sub == "branch" and any(a in ("-D", "--delete --force") for a in rest):
        return "ask", "force-deletes a branch"
    if sub in ("checkout", "restore") and "." in rest:
        return "ask", "discards every local change"
    return None


def decide(data):
    tool = data.get("tool_name") or ""
    ti = data.get("tool_input") or {}
    if tool in FILE_TOOLS:
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        if is_secret(path):
            return "deny", SECRET_REASON.format(path)
        return None
    if tool == "Grep":
        path = ti.get("path") or ""
        if is_secret(path) or is_secret(os.path.join(path, "x")):
            return "deny", SECRET_REASON.format(path)
        return None
    if tool != "Bash":
        return None
    command = ti.get("command") or ""
    try:
        parts = segments(command)
    except ValueError:
        return (
            "ask",
            "The guard couldn't parse this command, so it asks rather than guesses.",
        )
    ask = None
    for tokens, piped in parts:
        for t in tokens[1:]:
            if is_secret(t):
                return "deny", SECRET_REASON.format(t)
        hit = risky(tokens, piped)
        if hit and hit[0] == "deny":
            return "deny", f"Blocked: this {hit[1]}."
        if hit and ask is None:
            ask = ("ask", f"This command {hit[1]}. Check it before it runs.")
    return ask


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    result = decide(data if isinstance(data, dict) else {})
    if result:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": result[0],
                        "permissionDecisionReason": result[1],
                    }
                }
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
