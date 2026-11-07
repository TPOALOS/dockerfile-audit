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


if __name__ == "__main__":
    unittest.main()
