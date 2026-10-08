"""The settings, the pre-commit secret scan and the example skill.

Run: python3 -m unittest discover -s tests   (or: python3 -m pytest)
The pre-commit tests build throwaway git repos in a temp folder. The fake
secret is generated at run time, so this repo itself never holds one.
"""

import json
import os
import random
import re
import shutil
import string
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS = os.path.join(ROOT, ".claude", "settings.json")
PRECOMMIT = os.path.join(ROOT, ".githooks", "pre-commit")


def settings():
    with open(SETTINGS, encoding="utf-8") as fh:
        return json.load(fh)


class Settings(unittest.TestCase):
    def test_secret_files_are_denied_by_permission_rules(self):
        deny = settings()["permissions"]["deny"]
        for rule in (
            "Read(./.env)",
            "Read(./.env.*)",
            "Read(./secrets/**)",
            "Read(~/.ssh/**)",
            "Edit(./.env)",
            "Edit(./secrets/**)",
        ):
            with self.subTest(rule):
                self.assertIn(rule, deny)

    def test_no_write_rules(self):
        """Claude Code matches file writes against Edit(...) rules only; a
        Write(...) rule would look like protection and do nothing."""
        p = settings()["permissions"]
        for rule in p.get("deny", []) + p.get("ask", []) + p.get("allow", []):
            self.assertFalse(rule.startswith("Write("), rule)

    def test_risky_commands_ask_first(self):
        ask = settings()["permissions"]["ask"]
        for rule in (
            "Bash(git push:*)",
            "Bash(git reset --hard:*)",
            "Bash(rm -rf:*)",
            "Bash(sudo:*)",
        ):
            with self.subTest(rule):
                self.assertIn(rule, ask)

    def test_bypass_mode_is_off(self):
        self.assertEqual(
            settings()["permissions"]["disableBypassPermissionsMode"], "disable"
        )

    def test_the_guard_hook_runs_before_reads_edits_and_shell(self):
        groups = settings()["hooks"]["PreToolUse"]
        hit = [g for g in groups if any("guard.py" in h["command"] for h in g["hooks"])]
        self.assertEqual(len(hit), 1)
        for tool in ("Read", "Edit", "Write", "Bash", "Grep"):
            self.assertRegex(tool, hit[0]["matcher"])


def fake_token():
    return "ghp_" + "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(36)
    )


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is not installed")
class PreCommitSecretScan(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="precommit-")
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        hooks = os.path.join(self.repo, ".githooks")
        os.makedirs(hooks)
        shutil.copy(PRECOMMIT, hooks)
        self.git("config", "core.hooksPath", ".githooks")

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def git(self, *args, env=None):
        return subprocess.run(
            ["git", "-C", self.repo, *args], capture_output=True, text=True, env=env
        )

    def stage(self, name, text):
        with open(os.path.join(self.repo, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        self.git("add", name)

    def test_a_staged_token_blocks_the_commit(self):
        self.stage("config.py", f'GITHUB_TOKEN = "{fake_token()}"\n')
        r = self.git("commit", "-m", "add config")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("secret", (r.stdout + r.stderr).lower())
        self.assertEqual(
            self.git("rev-list", "--all").stdout.strip(), "", "nothing was committed"
        )

    def test_a_clean_commit_goes_through(self):
        self.stage("app.py", "print('hello')\n")
        r = self.git("commit", "-m", "add app")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_without_gitleaks_the_commit_is_refused(self):
        env = dict(os.environ, PATH="/usr/bin:/bin")  # git, but no gitleaks
        self.stage("app.py", "print('hello')\n")
        r = self.git("commit", "-m", "add app", env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gitleaks", (r.stdout + r.stderr).lower())


class ExampleSkill(unittest.TestCase):
    def test_frontmatter_names_it_and_limits_its_tools(self):
        path = os.path.join(ROOT, ".claude", "skills", "pr-description", "SKILL.md")
        text = open(path, encoding="utf-8").read()
        fm = re.match(r"---\n(.*?)\n---\n", text, re.S).group(1)
        self.assertRegex(fm, r"(?m)^name: pr-description$")
        desc = re.search(r"(?ms)^description:(.*?)(?=^[a-z-]+:)", fm).group(1)
        self.assertGreater(len(" ".join(desc.replace(">-", "").split())), 40)
        tools = re.search(r"(?m)^allowed-tools:(.*)$", fm).group(1)
        self.assertNotIn("Bash(*)", tools)
        self.assertNotIn("Write", tools)
        self.assertNotIn("Edit", tools)

    def test_claude_md_template_has_the_house_rules(self):
        text = open(os.path.join(ROOT, "CLAUDE.md"), encoding="utf-8").read()
        for part in ("## Commands", "## Guard rails", ".env", "git push"):
            self.assertIn(part, text)


if __name__ == "__main__":
    unittest.main(verbosity=1)
