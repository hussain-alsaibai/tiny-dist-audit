# tiny-dist-audit

> **What is actually inside the file you shipped?** Deterministic release-artifact
> manifests and drift detection for Python wheels, sdists, and trees.
> Zero dependencies, stdlib only, one module.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://github.com/hussain-alsaibai/tiny-dist-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)]()

## Why

Every release pipeline produces a file and then trusts it. Nothing in the
process says what that file **contains**, what it **declares**, or whether the
artifact downloaded today is the same one that was reviewed last week.

The tools that dominated the last week of developer-tool chatter — packed
binaries, agent proxies, single-file runtimes — share a failure mode: their
published bugs are *accounting* bugs. A salt that differs between parallel
runs. A telemetry ping that reports a command that never finished. A pipeline
file resolved five times per call. None of it is visible unless somebody
compares what the artifact claims against what it holds.

For Python distributions the comparison is cheap. This does it in one
dependency-free module:

```bash
pip install tiny-dist-audit
dist-audit check dist/*.whl --baseline dist-manifest.json --fail-on high
```

You commit `dist-manifest.json` at release time. Every later build is diffed
against it in CI. If a file appeared, vanished, or changed bytes, the job says
so, by name.

## Install

```bash
pip install tiny-dist-audit
```

Python 3.9+. No third-party packages. The CLI entry point is `dist-audit`;
`python -m tiny_dist_audit` does the same thing.

## Quick start

```python
from tiny_dist_audit import build_manifest, dumps, check

manifest = build_manifest("dist/tiny_thing-1.0.0-py3-none-any.whl")
print(manifest["artifact"]["tree_digest"])
print(manifest["metadata"]["requires_python"])
print(len(manifest["files"]))          # every entry, with its sha256

open("dist-manifest.json", "w").write(dumps(manifest))
```

Two builds of the same tree produce **byte-identical** output, which is the
only reason a committed manifest is useful. File ordering is sorted, metadata
keys are sorted, and the tree digest is computed over a canonical
`<sha256>  <path>` listing rather than over dict insertion order.

## Drift

```bash
dist-audit check dist/tiny_thing-1.0.1-py3-none-any.whl \
  --baseline dist-manifest.json --fail-on high
```

```
artifact : tiny_thing-1.0.1-py3-none-any.whl (wheel, 7 files)
tree     : 4b1f8e2c9a0d3f17
name/ver : tiny-thing 1.0.1
drift    : 1 changed, 1 metadata field(s) changed
signature: unsigned
severity : high (fail-on high)
  ~ changed tiny_thing/core.py
  ! metadata 'version' changed: '1.0.0' -> '1.0.1'
```

Exit codes:

| code | meaning |
|------|---------|
| 0 | nothing at or above `--fail-on` |
| 2 | usage error, or the artifact could not be read |
| 4 | `diff` found differences |
| 5 | `check` found drift at or above `--fail-on` |

Severities, worst finding wins: `changed` or `removed` file is **high**, an
**added** file is medium, a metadata change is **low**, and a credential-shaped
path name (`.env`, `.pem`, `id_rsa`, `.pypirc`, `.aws/credentials`, …) is
**high**. `requires_dist` is compared as a sorted set, because reordering an
unordered dependency list is not a release difference.

## The dependency change you did not make

`Requires-Dist` is the field that silently pulls a new transitive tree into
every install. It is also the field most release tools ignore. Here it is part
of the manifest and part of the diff:

```python
from tiny_dist_audit import build_manifest, diff_manifests

old = build_manifest("dist/old.whl")
new = build_manifest("dist/new.whl")
drift = diff_manifests(old, new)
for field, (before, after) in drift.metadata_changed.items():
    print(field, before, "->", after)
```

## What the signature does — and does not do

`sign()` attaches an HMAC-SHA256 over the canonical manifest body; `verify()`
recomputes it. This catches:

- a manifest edited by hand between releases,
- a manifest substituted in transit,
- a CI job that regenerated the baseline and lost the signature.

It does **not** prove that the artifact on disk is the one the signer saw, and
it is not a replacement for a public-key signature or an in-toto attestation.
An HMAC key that lives in the same CI secrets store as the build can be used by
anyone who can run the build. Say that out loud when you report a green check —
a signature over the wrong thing reads exactly like a signature over the right
thing.

```python
import os
from tiny_dist_audit import build_manifest, sign, verify

key = os.environ["DIST_AUDIT_KEY"].encode()
signed = sign(build_manifest("dist/pkg.whl"), key)
signed["files"]["pkg/__init__.py"] = "0" * 64   # tamper
assert verify(signed, key) is False
```

`check()` reports `signature` as one of `unsigned`, `valid`,
`unverified-no-key`, or `INVALID`. `INVALID` escalates the run to **critical**
whatever `--fail-on` says. A signed baseline audited without a key is reported
as `unverified-no-key` — never as `valid`, because silence is not verification.

## Seeing only names, never contents

`find_risky_paths()` is a **name** check. It flags `.env`, `*.pem`, `*.key`,
`id_rsa`, `.pypirc`, `.npmrc`, `.aws/credentials` and friends inside the
artifact. It cannot see a token committed into `settings.py`, and it will not
flag it. `environment.py` is deliberately *not* flagged — matching on the
substring `env` would make the check useless.

## API

| function | purpose |
|---|---|
| `build_manifest(path)` | manifest for a wheel, sdist, or directory |
| `dumps(manifest)` | stable JSON text (sorted files and keys) |
| `parse_metadata(text)` | PEP 566 header subset → dict; repeats become lists |
| `diff_manifests(old, new)` | `Drift` with added / removed / changed / metadata |
| `check(path, baseline=None, *, key=None, fail_on="high")` | full report, never exits |
| `find_risky_paths(manifest)` | credential-shaped **names** |
| `sign(manifest, key)` / `verify(manifest, key)` | HMAC-SHA256 roundtrip |

`main(argv)` returns the exit code instead of calling `sys.exit`, so a test can
assert on it.

## What is skipped, and why

`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`, `.venv`,
`node_modules`, `.eggs`, `*.egg-info`, and anything under `.git` are excluded
from a tree manifest. They are not shipped and they change on every test run.
Including them makes two identical trees hash differently, which would make the
digest worthless as a baseline.

## Limits, stated plainly

- **No attestation.** This is a manifest, not Sigstore. It binds contents to a
  digest; it does not bind identity to a build.
- **Names, not contents.** The leak scan matches path names only.
- **Python distributions.** Wheels, sdists, and directory trees. Not tarballs
  of arbitrary layout, not `.deb`, not container images.
- **No network.** It never talks to PyPI and never verifies that a published
  file matches your local one. Compare digests with `pip download` yourself, or
  wire this into the job that does.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers the parser (folding, repeated fields), manifest determinism,
drift in each direction, `requires_dist` reordering, HMAC tampering, and the
CLI exit codes. The signature tests include a negative control — `verify({})`
must be `False` — because a fail-open `verify` is the failure this library
exists to prevent.

## License

MIT
