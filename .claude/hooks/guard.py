#!/usr/bin/env python3
"""Guard hook for Claude Code (PreToolUse). Two guards, one file:

1. Secret files are blocked: .env files, anything under secrets/ or ~/.ssh,
   private keys and cloud credentials, whether reached by Read, Edit, Write,
   Grep (its path or glob) or a shell command such as `cat .env` or `cat .en?`.
2. Risky commands ask first: pushes, destructive git, recursive deletes,
   sudo, piping a download into a shell, publishing a package. A force push
   is denied outright, also behind `git -C dir` or inside `bash -c "..."`.
3. The commands settings.json allows without a prompt stay read-only: git
   diff/log/show with --output, --ext-diff or --textconv, and pytest with
   --basetemp, -p, -c or --rootdir, are denied.

Everything else passes untouched. A command the hook can't parse asks rather
than guesses. Standard library only; the tests in tests/test_guard.py show
each guard firing. Registered in .claude/settings.json.

This is a guard rail, not a sandbox: it reads the command text, so a script
that reads a secret inside itself is out of its sight. The permission rules
in settings.json are the first layer; this hook is the second.
"""

import fnmatch
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
ENV_SAMPLES = (".env", ".env.local", ".env.production")
GLOB_CHARS = set("*?[")
# Options before git's subcommand; the ones in GIT_GLOBAL_WITH_VALUE take the next token.
GIT_GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
# git diff/log/show/format-patch are allowed without a prompt, so the flags that
# make them write a file or run an outside program are denied.
GIT_READ_SUBS = {"diff", "log", "show", "format-patch"}
GIT_WRITE_FLAGS = ("--output", "--ext-diff", "--textconv")
# pytest is allowed without a prompt: --basetemp deletes the folder it names, and
# -p / -c / --rootdir load plugins or config from elsewhere.
PYTEST_DENY = ("--basetemp", "--config-file", "--rootdir")
DOWNLOAD_SUBST = re.compile(r"[$<]\([^)]*\b(curl|wget)\b")
MAX_DEPTH = 3


def env_glob(pattern):
    """True when a shell glob such as .en? or .env* would match an env file."""
    name = pattern.replace("\\", "/").split("/")[-1]
    if not GLOB_CHARS & set(name) or not name.startswith((".", "[")):
        return False
    return any(fnmatch.fnmatchcase(sample, name) for sample in ENV_SAMPLES)


def is_secret(path):
    if not path or path.startswith("-"):
        return False
    p = os.path.normpath(os.path.expanduser(path))
    parts = p.replace("\\", "/").split("/")
    name = parts[-1]
    if name.endswith(SAFE_SUFFIXES):
        return False
    if name == ".env" or name.startswith(".env.") or env_glob(name):
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
    if cmd in ("pytest", "py.test") or (
        cmd.startswith("python") and args[:2] == ["-m", "pytest"]
    ):
        flags = args if cmd in ("pytest", "py.test") else args[2:]
        for i, a in enumerate(flags):
            if a.split("=", 1)[0] in PYTEST_DENY or a in ("-c",) or a.startswith("-c="):
                return "deny", f"runs pytest with {a.split('=', 1)[0]}, which can delete a folder or load outside config"
            if a.startswith("-p") and not a.startswith("--"):
                value = a[2:].lstrip("=") or (flags[i + 1] if i + 1 < len(flags) else "")
                if not value.startswith("no:"):
                    return "deny", "runs pytest with -p, which loads a plugin from outside the tests"
        return None
    if cmd != "git":
        return None
    while args and args[0].startswith("-"):  # git -C dir / -c k=v before the subcommand
        args = args[2:] if args[0] in GIT_GLOBAL_WITH_VALUE else args[1:]
    if not args:
        return None
    sub, rest = args[0], args[1:]
    if sub in GIT_READ_SUBS and any(a.split("=", 1)[0] in GIT_WRITE_FLAGS for a in rest):
        return "deny", f"runs git {sub} with a flag that writes a file or runs an outside program"
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
        glob = ti.get("glob") or ""
        if glob and (is_secret(glob) or env_glob(glob)):
            return "deny", SECRET_REASON.format(glob)
        return None
    if tool != "Bash":
        return None
    return check_command(ti.get("command") or "")


def check_command(command, depth=0):
    if depth > MAX_DEPTH:
        return "ask", "The guard couldn't follow this command's nesting, so it asks."
    try:
        parts = segments(command)
    except ValueError:
        return (
            "ask",
            "The guard couldn't parse this command, so it asks rather than guesses.",
        )
    ask = None
    if DOWNLOAD_SUBST.search(command):
        ask = ("ask", "This command runs downloaded text. Check it before it runs.")
    for tokens, piped in parts:
        for t in tokens[1:]:
            if is_secret(t):
                return "deny", SECRET_REASON.format(t)
        if tokens and os.path.basename(tokens[0]) in SHELLS and "-c" in tokens[1:-1]:
            inner = check_command(tokens[tokens.index("-c", 1) + 1], depth + 1)
            if inner and inner[0] == "deny":
                return inner
            if inner and ask is None:
                ask = inner
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
