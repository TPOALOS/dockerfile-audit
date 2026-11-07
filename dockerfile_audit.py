#!/usr/bin/env python3
"""dockerfile-audit - security-focused linter for Dockerfiles.

Offline and read-only. Flags running as root, unpinned base images, secrets in
ENV/ARG, curl-pipe-shell installs, remote ADD and similar risks, with a fix for
each. Standard library only. Exit code 0 = clean, 1 = findings, 2 = error.
"""
import argparse
import os
import re
import sys

__version__ = "1.0.0"

SECRET_NAME = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential)")
CURL_PIPE = re.compile(r"(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
ARCHIVE = re.compile(r"(?i)\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$")


def logical_lines(text):
    """Return [(lineno, INSTRUCTION, args)] with continuations joined and comments dropped."""
    out, buf, start = [], "", 0
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if buf and line.lstrip().startswith("#"):
            continue
        if not buf:
            start = no
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.strip().split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    if buf.strip():
        parts = buf.strip().split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return out


def parse_from(args):
    toks = [t for t in args.split() if not t.startswith("--")]
    image = toks[0] if toks else ""
    alias = toks[2].lower() if len(toks) >= 3 and toks[1].lower() == "as" else None
    return image, alias


def image_problem(image, stages):
    """Return a message when the base image reference is not pinned, else None."""
    if not image or image.lower() == "scratch" or image.lower() in stages or "$" in image:
        return None
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "%s has no tag, so it implicitly uses :latest" % image
    if last.endswith(":latest"):
        return "%s uses the moving :latest tag" % image
    return None


def audit_text(text, has_dockerignore=None):
    """Return list of (severity, rule, lineno, message, fix)."""
    instrs = logical_lines(text)
    out = []
    add = lambda sev, rule, no, msg, fix: out.append((sev, rule, no, msg, fix))
    stages, last_from = set(), None
    for no, ins, args in instrs:
        if ins == "FROM":
            image, alias = parse_from(args)
            msg = image_problem(image, stages)
            if msg:
                add("MEDIUM", "unpinned-base-image", no, msg, "pin a specific version tag or an @sha256 digest")
            if alias:
                stages.add(alias)
            last_from = no
    final = [(n, i, a) for n, i, a in instrs if last_from is None or n >= last_from]

    users = [(n, a.split(":")[0].strip().lower()) for n, i, a in final if i == "USER"]
    if not users:
        add("HIGH", "runs-as-root", last_from, "final image has no USER instruction, so it runs as root",
            "create an unprivileged user and add `USER appuser`")
    elif users[-1][1] in ("root", "0"):
        add("HIGH", "runs-as-root", users[-1][0], "final USER is root", "switch to an unprivileged user")
    if instrs and not any(i == "HEALTHCHECK" for _, i, _ in final):
        add("LOW", "no-healthcheck", None, "final image defines no HEALTHCHECK", "add a HEALTHCHECK instruction")

    for no, ins, args in instrs:
        if ins in ("ENV", "ARG"):
            for pair in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)(=(?:\"[^\"]*\"|'[^']*'|\S*))?", args if ins == "ARG" else args):
                name, val = pair
                if not SECRET_NAME.search(name):
                    continue
                has_value = bool(val) and val not in ("=", '=""', "=''")
                if has_value or (ins == "ENV" and len(args.split()) > 1 and "=" not in args):
                    add("HIGH", "secret-in-image", no, "%s %s carries a secret value into the image layers" % (ins, name),
                        "use BuildKit secrets (--mount=type=secret) or inject at runtime")
                elif ins == "ARG":
                    add("LOW", "secret-build-arg", no, "ARG %s is recorded in image history" % name,
                        "use BuildKit secrets instead of build args for credentials")
                break
        elif ins == "RUN":
            if CURL_PIPE.search(args):
                add("MEDIUM", "curl-pipe-shell", no, "downloads and executes a script without verification",
                    "download, verify a checksum or signature, then run")
            if re.search(r"chmod\s+(?:-R\s+)?0?777\b", args):
                add("MEDIUM", "chmod-777", no, "world-writable permissions", "grant the minimum needed (e.g. 755 or 644)")
            if re.search(r"\bsudo\b", args):
                add("LOW", "sudo-in-run", no, "sudo is unnecessary during build and bloats the image", "run as root during build, drop with USER later")
            if re.search(r"apt-get\s+install", args) and "--no-install-recommends" not in args:
                add("LOW", "apt-recommends", no, "apt-get install without --no-install-recommends adds extra packages",
                    "add --no-install-recommends")
        elif ins == "ADD":
            srcs = [t for t in args.split() if not t.startswith("--")]
            if srcs and re.match(r"(?i)https?://", srcs[0]):
                add("MEDIUM", "remote-add", no, "ADD fetches a remote URL with no integrity check",
                    "use curl/wget with checksum verification, or COPY a vendored file")
            elif srcs and not ARCHIVE.search(srcs[0]):
                add("LOW", "add-instead-of-copy", no, "ADD has extra behaviour (archives, URLs); COPY is clearer", "use COPY")
        elif ins == "COPY" and re.match(r"(?:--\S+\s+)*\.\s", args + " ") and has_dockerignore is False:
            add("LOW", "copy-all-no-dockerignore", no, "COPY . with no .dockerignore may include .git, .env and keys",
                "add a .dockerignore")
        elif ins == "EXPOSE" and re.search(r"(?<![\d])22(?:/\w+)?(?![\d])", args):
            add("MEDIUM", "expose-ssh", no, "port 22 is exposed", "avoid running sshd in containers; use exec/kubectl")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Security linter for Dockerfiles (offline).")
    ap.add_argument("files", nargs="*", default=["Dockerfile"])
    ap.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    limit, count = SEV[args.min_severity], 0
    for path in args.files:
        try:
            with open(path, errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("dockerfile-audit: %s" % exc, file=sys.stderr)
            return 2
        di = os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(path)), ".dockerignore"))
        for sev, rule, no, msg, fix in sorted(audit_text(text, di), key=lambda f: (SEV[f[0]], f[2] or 0)):
            if SEV[sev] > limit:
                continue
            count += 1
            print("%-6s %-24s %s%s: %s\n         fix: %s" % (sev, rule, path, ":%d" % no if no else "", msg, fix))
    print("dockerfile-audit: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
