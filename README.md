# dockerfile-audit

A security-focused linter for Dockerfiles. It works **offline** and is read-only:
run it on a Dockerfile and it lists risks with a suggested fix for each.
One file, standard library only.

## Usage

```bash
python3 dockerfile_audit.py                      # ./Dockerfile
python3 dockerfile_audit.py services/api/Dockerfile Dockerfile.dev --min-severity MEDIUM
```

Example output:

```
HIGH   runs-as-root             Dockerfile:1: final image has no USER instruction, so it runs as root
         fix: create an unprivileged user and add `USER appuser`
HIGH   secret-in-image          Dockerfile:3: ENV API_TOKEN carries a secret value into the image layers
         fix: use BuildKit secrets (--mount=type=secret) or inject at runtime
MEDIUM unpinned-base-image      Dockerfile:1: ubuntu has no tag, so it implicitly uses :latest
         fix: pin a specific version tag or an @sha256 digest
```

## Checks

| Rule | Severity | What it flags |
|------|----------|---------------|
| `runs-as-root` | HIGH | final stage has no `USER`, or the last `USER` is root/0 |
| `secret-in-image` | HIGH | `ENV`/`ARG` with a secret-looking name (password, token, api key, ...) and a value |
| `unpinned-base-image` | MEDIUM | `FROM` without a tag, with `:latest`, and not pinned by digest (stage aliases, `scratch` and `${VAR}` images are skipped) |
| `curl-pipe-shell` | MEDIUM | `curl ... \| sh` style installs |
| `remote-add` | MEDIUM | `ADD` from an http(s) URL |
| `chmod-777` | MEDIUM | world-writable permissions |
| `expose-ssh` | MEDIUM | `EXPOSE 22` |
| `secret-build-arg` | LOW | secret-named `ARG` without a default (still visible in image history) |
| `add-instead-of-copy` | LOW | local `ADD` that is not an archive |
| `copy-all-no-dockerignore` | LOW | `COPY .` with no `.dockerignore` next to the Dockerfile |
| `apt-recommends` | LOW | `apt-get install` without `--no-install-recommends` |
| `sudo-in-run` | LOW | `sudo` during build |
| `no-healthcheck` | LOW | final stage has no `HEALTHCHECK` |

Exit codes: `0` clean, `1` findings, `2` unreadable file.

## Limits

Line-based parsing: heredocs, `ONBUILD`, and variables expanded at build time are not
interpreted. It cannot know what your base image already contains (for example a
non-root default user). Treat findings as review hints.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
