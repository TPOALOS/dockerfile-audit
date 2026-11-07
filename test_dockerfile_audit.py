import contextlib
import io
import json
import os
import tempfile
import unittest

import dockerfile_audit as da

GOOD = """FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
RUN useradd -m appuser
USER appuser
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "app/main.py"]
"""


def rules(text, di=None):
    return {(f[0], f[1]) for f in da.audit_text(text, di)}


class ParseTests(unittest.TestCase):
    def test_continuations_and_comments(self):
        t = "# c\nRUN apt-get update && \\\n   # inner comment\n   apt-get install -y x\nUSER a\n"
        lines = da.logical_lines(t)
        self.assertEqual(lines[0][1], "RUN")
        self.assertIn("apt-get install", lines[0][2])
        self.assertEqual(lines[1], (5, "USER", "a"))


class RuleTests(unittest.TestCase):
    def test_good_clean(self):
        self.assertEqual(da.audit_text(GOOD, True), [])

    def test_base_images(self):
        self.assertIn(("MEDIUM", "unpinned-base-image"), rules("FROM ubuntu\nUSER a\n"))
        self.assertIn(("MEDIUM", "unpinned-base-image"), rules("FROM node:latest\nUSER a\n"))
        self.assertNotIn(("MEDIUM", "unpinned-base-image"), rules("FROM node:20\nUSER a\n"))
        self.assertNotIn(("MEDIUM", "unpinned-base-image"), rules("FROM alpine@sha256:" + "a" * 64 + "\nUSER a\n"))
        self.assertNotIn(("MEDIUM", "unpinned-base-image"), rules("FROM scratch\nUSER a\n"))
        self.assertNotIn(("MEDIUM", "unpinned-base-image"), rules("ARG BASE\nFROM ${BASE}\nUSER a\n"))
        self.assertIn(("MEDIUM", "unpinned-base-image"),
                      rules("FROM --platform=linux/amd64 localhost:5000/app\nUSER a\n"))

    def test_multistage_alias_not_flagged(self):
        t = "FROM golang:1.22 AS build\nRUN go build\nFROM build\nUSER a\n"
        self.assertNotIn(("MEDIUM", "unpinned-base-image"), rules(t))

    def test_root_user(self):
        self.assertIn(("HIGH", "runs-as-root"), rules("FROM python:3.12\nCMD x\n"))
        self.assertIn(("HIGH", "runs-as-root"), rules("FROM python:3.12\nUSER root\n"))
        self.assertIn(("HIGH", "runs-as-root"), rules("FROM python:3.12\nUSER app\nUSER 0\n"))
        self.assertNotIn(("HIGH", "runs-as-root"), rules("FROM python:3.12\nUSER 1000:1000\n"))

    def test_user_only_in_builder_stage_still_root(self):
        t = "FROM python:3.12 AS build\nUSER app\nFROM python:3.12\nCMD x\n"
        self.assertIn(("HIGH", "runs-as-root"), rules(t))

    def test_secrets(self):
        self.assertIn(("HIGH", "secret-in-image"), rules("FROM a:1\nENV API_TOKEN=abc123\nUSER u\n"))
        self.assertIn(("HIGH", "secret-in-image"), rules("FROM a:1\nENV DB_PASSWORD hunter2\nUSER u\n"))
        self.assertIn(("HIGH", "secret-in-image"), rules("FROM a:1\nARG PASSWORD=x\nUSER u\n"))
        self.assertIn(("LOW", "secret-build-arg"), rules("FROM a:1\nARG NPM_TOKEN\nUSER u\n"))
        self.assertNotIn(("HIGH", "secret-in-image"), rules("FROM a:1\nENV PATH=/x\nUSER u\n"))

    def test_run_checks(self):
        r = rules("FROM a:1\nRUN curl -sSL https://x.example/i.sh | sh\nRUN chmod -R 777 /app\n"
                  "RUN sudo ls\nRUN apt-get install -y curl\nUSER u\n")
        for e in (("MEDIUM", "curl-pipe-shell"), ("MEDIUM", "chmod-777"), ("LOW", "sudo-in-run"), ("LOW", "apt-recommends")):
            self.assertIn(e, r)

    def test_add(self):
        self.assertIn(("MEDIUM", "remote-add"), rules("FROM a:1\nADD https://x.example/f.tgz /f\nUSER u\n"))
        self.assertIn(("LOW", "add-instead-of-copy"), rules("FROM a:1\nADD app.py /app.py\nUSER u\n"))
        self.assertNotIn(("LOW", "add-instead-of-copy"), rules("FROM a:1\nADD rootfs.tar.gz /\nUSER u\n"))

    def test_copy_all_and_expose(self):
        self.assertIn(("LOW", "copy-all-no-dockerignore"), rules("FROM a:1\nCOPY . /app\nUSER u\n", False))
        self.assertNotIn(("LOW", "copy-all-no-dockerignore"), rules("FROM a:1\nCOPY . /app\nUSER u\n", True))
        self.assertIn(("MEDIUM", "expose-ssh"), rules("FROM a:1\nEXPOSE 22 80\nUSER u\n"))
        self.assertNotIn(("MEDIUM", "expose-ssh"), rules("FROM a:1\nEXPOSE 2222 8022\nUSER u\n"))

    def test_healthcheck_rule(self):
        self.assertIn(("LOW", "no-healthcheck"), rules("FROM a:1\nUSER u\n"))


class CliTests(unittest.TestCase):
    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "Dockerfile")
            with open(p, "w") as fh:
                fh.write(GOOD)
            self.assertEqual(da.main([p]), 0)
            with open(p, "w") as fh:
                fh.write("FROM ubuntu\n")
            self.assertEqual(da.main([p]), 1)
            self.assertEqual(da.main([p, "--min-severity", "HIGH"]), 1)
            self.assertEqual(da.main([os.path.join(d, "nope")]), 2)


def rule_names(text):
    return {f[1] for f in da.audit_text(text)}


class NewRuleTests(unittest.TestCase):
    def test_pip_cache(self):
        self.assertIn("pip-cache", rule_names(GOOD.replace(" --no-cache-dir", "")))
        self.assertNotIn("pip-cache", rule_names(GOOD))
        self.assertNotIn("pip-cache", rule_names("ENV PIP_NO_CACHE_DIR=1\n" + GOOD.replace(" --no-cache-dir", "")))

    def test_apt_cache(self):
        bad = GOOD + "RUN apt-get update && apt-get install -y --no-install-recommends curl\n"
        self.assertIn("apt-cache", rule_names(bad))
        ok = GOOD + "RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n"
        self.assertNotIn("apt-cache", rule_names(ok))

    def test_apk_cache(self):
        self.assertIn("apk-cache", rule_names("FROM alpine:3.20\nRUN apk add curl\n"))
        self.assertNotIn("apk-cache", rule_names("FROM alpine:3.20\nRUN apk add --no-cache curl\n"))

    def test_insecure_download(self):
        for cmd in ("curl -k https://x.example/a -o a", "curl --insecure -sSL https://x/a", "wget --no-check-certificate https://x/a"):
            self.assertIn(("HIGH", "insecure-download"), {(f[0], f[1]) for f in da.audit_text(GOOD + "RUN " + cmd + "\n")}, cmd)
        self.assertNotIn("insecure-download", rule_names(GOOD + "RUN curl -fsSL https://x/a -o a\n"))

    def test_git_clone_with_credentials(self):
        bad = GOOD + "RUN git clone https://user:pass1234@github.com/org/repo.git\n"  # secretscan:ignore
        self.assertIn("secret-in-image", rule_names(bad))
        self.assertNotIn("secret-in-image", rule_names(GOOD + "RUN git clone https://github.com/org/repo.git\n"))

    def test_good_dockerfile_still_clean(self):
        self.assertEqual(da.audit_text(GOOD), [])


class IgnoreTests(unittest.TestCase):
    def test_same_line_ignore(self):
        t = GOOD + "RUN curl -k https://x/a -o a  # dockerfile-audit: ignore[insecure-download]\n"
        self.assertNotIn("insecure-download", rule_names_with_ignores(t))

    def test_line_above_ignore(self):
        t = GOOD + "# dockerfile-audit: ignore[insecure-download]\nRUN curl -k https://x/a -o a\n"
        self.assertNotIn("insecure-download", rule_names_with_ignores(t))

    def test_wrong_rule_does_not_silence(self):
        t = GOOD + "RUN curl -k https://x/a -o a  # dockerfile-audit: ignore[chmod-777]\n"
        self.assertIn("insecure-download", rule_names_with_ignores(t))

    def test_ignore_file(self):
        t = "# dockerfile-audit: ignore-file[runs-as-root]\nFROM ubuntu:24.04\nHEALTHCHECK CMD true\n"
        self.assertEqual(rule_names_with_ignores(t), set())

    def test_does_not_leak_to_other_lines(self):
        t = GOOD + "RUN curl -k https://x/a -o a  # dockerfile-audit: ignore\nRUN curl -k https://y/b -o b\n"
        found = da.apply_ignores(t, da.audit_text(t))
        self.assertEqual(sum(1 for f in found if f[1] == "insecure-download"), 1)


def rule_names_with_ignores(text):
    return {f[1] for f in da.apply_ignores(text, da.audit_text(text))}


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = da.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class FormatTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._t.name, "Dockerfile")
        with open(self.path, "w") as fh:
            fh.write("FROM ubuntu\nENV API_TOKEN=abcdef123456\n")

    def tearDown(self):
        self._t.cleanup()

    def test_json(self):
        code, out, _ = run_main(self.path, "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertIn("secret-in-image", {d["rule"] for d in data})
        self.assertEqual({"severity", "rule", "file", "line", "message", "fix"}, set(data[0]))

    def test_json_never_contains_the_secret_value(self):
        _, out, _ = run_main(self.path, "--format", "json")
        self.assertNotIn("abcdef123456", out)

    def test_sarif(self):
        _, out, _ = run_main(self.path, "--format", "sarif")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(levels["secret-in-image"], "error")
        self.assertEqual(levels["unpinned-base-image"], "warning")

    def test_min_severity_with_json(self):
        _, out, _ = run_main(self.path, "--format", "json", "--min-severity", "HIGH")
        self.assertTrue(all(d["severity"] == "HIGH" for d in json.loads(out)))

    def test_suppression_applies_in_cli(self):
        with open(self.path, "w") as fh:
            fh.write("# dockerfile-audit: ignore-file\nFROM ubuntu\n")
        self.assertEqual(run_main(self.path)[0], 0)

    def test_missing_file(self):
        self.assertEqual(run_main(os.path.join(self._t.name, "nope"))[0], 2)


if __name__ == "__main__":
    unittest.main()
