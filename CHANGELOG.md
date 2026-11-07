# Changelog

## 1.1.0

- `--format json` and `--format sarif`
- New rules: `insecure-download` (HIGH), `pip-cache`, `apt-cache`, `apk-cache` (LOW); credentials in `git clone`
  URLs are reported as `secret-in-image`
- `# dockerfile-audit: ignore[rule]` and `ignore-file[rule]` suppression comments
- The new LOW rules can add findings to Dockerfiles that were clean before; use `--min-severity MEDIUM` for the
  old threshold
- Installable with pip (`dockerfile-audit` command), CI on Linux and macOS

## 1.0.0

Initial release.
