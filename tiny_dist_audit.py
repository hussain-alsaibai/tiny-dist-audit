"""tiny-dist-audit — release artifact manifest + drift detection.

A build produces a file. Nothing about that file says what is *inside* it, what
it declares, or whether today's download is byte-identical to the one that was
reviewed last week. This module fills that gap for Python distributions
(wheels, sdists, `.dist-info` trees) with no third-party dependencies.

Three operations, all stdlib-only:

    manifest = build_manifest("dist/tiny_thing-1.2.0-py3-none-any.whl")
    diff     = diff_manifests(old_manifest, new_manifest)
    ok       = verify(signature, key, manifest)

The manifest is deterministic JSON. Two builds of the same tree on different
days produce the same bytes, so a CI job can commit it and diff it per tag.

Honest scope note: the tree digest binds the manifest to the *contents* it
describes. Without a signature it does not stop an attacker who can rewrite
both the artifact and the manifest — see `sign()`/`verify()` for that, and the
README for what HMAC keys do and do not buy you.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

__version__ = "0.1.0"

MANIFEST_SCHEMA = "tiny-dist-audit/1"
TREE_DIGEST_SCHEMA = "tiny-dist-audit-tree/1"

# Files that a distribution should not be shipping. These are warnings, not
# verdicts: a wheel with a test fixture may be legitimate.
RISKY_PATH_MARKERS = (
    ".env",
    ".pem",
    ".key",
    "id_rsa",
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
)

# Build and tool caches are noise in a release manifest: they are not shipped,
# and including them makes two identical trees hash differently.
_SKIP_DIR_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "node_modules",
    ".eggs",
}

# Severity ordering, lowest concern first.
_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class DistAuditError(ValueError):
    """Raised when an artifact cannot be read at all."""


# --------------------------------------------------------------------------
# hashing helpers
# --------------------------------------------------------------------------


def _digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    """Serialise deterministically so signatures are reproducible."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _tree_digest(files: Dict[str, str]) -> str:
    """Hash (path, sha256) pairs in sorted order.

    A map alone is not ordered, so the digest is over a canonical
    line-per-entry text form: ``<sha256>  <path>\\n``.
    """
    body = "".join(f"{files[k]}  {k}\n" for k in sorted(files))
    return _digest_hex(body.encode("utf-8"))


# --------------------------------------------------------------------------
# metadata parsing (PEP 566 subset)
# --------------------------------------------------------------------------


def parse_metadata(text: str) -> Dict[str, Any]:
    """Parse a METADATA / PKG-INFO file into a mapping.

    Only the fields a drift check needs are promoted to scalars. Repeated
    fields (`Requires-Dist`, `Classifier`, ...) become lists. Continuation
    lines (RFC 822 folding) are joined.
    """
    fields: Dict[str, Any] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        if raw.startswith((" ", "\t")) and current:
            previous = fields[current]
            joined = raw.strip()
            if isinstance(previous, list):
                previous[-1] = (previous[-1] + " " + joined).strip()
            else:
                fields[current] = (previous + " " + joined).strip()
            continue
        if not raw or raw.startswith("#"):
            continue
        if ":" not in raw:
            continue
        name, _, value = raw.partition(":")
        name = name.strip()
        value = value.strip()
        current = name
        if name in fields:
            existing = fields[name]
            if isinstance(existing, list):
                existing.append(value)
            else:
                fields[name] = [existing, value]
        else:
            fields[name] = value
    return fields


# --------------------------------------------------------------------------
# artifact reading
# --------------------------------------------------------------------------


def _read_wheel(path: str) -> Tuple[Dict[str, str], Dict[str, bytes]]:
    files: Dict[str, str] = {}
    meta_raw: Dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                data = zf.read(info)
                files[name] = _digest_hex(data)
                base = name.rsplit("/", 1)[-1]
                if base in ("METADATA", "WHEEL", "RECORD"):
                    meta_raw[base] = data
    except (zipfile.BadZipFile, OSError) as exc:
        raise DistAuditError(f"not a readable wheel: {path}: {exc}") from exc
    return files, meta_raw


def _read_sdist(path: str) -> Tuple[Dict[str, str], Dict[str, bytes]]:
    files: Dict[str, str] = {}
    meta_raw: Dict[str, bytes] = {}
    try:
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                data = fh.read()
                name = member.name
                files[name] = _digest_hex(data)
                base = name.rsplit("/", 1)[-1]
                if base == "PKG-INFO" and "PKG-INFO" not in meta_raw:
                    meta_raw["PKG-INFO"] = data
    except (tarfile.TarError, OSError) as exc:
        raise DistAuditError(f"not a readable sdist: {path}: {exc}") from exc
    return files, meta_raw


def _read_tree(root: str) -> Tuple[Dict[str, str], Dict[str, bytes]]:
    files: Dict[str, str] = {}
    meta_raw: Dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in _SKIP_DIR_PARTS
            and not d.startswith(".git")
            and not d.endswith(".egg-info")
        ]
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, "rb") as handle:
                    data = handle.read()
            except OSError as exc:
                raise DistAuditError(f"cannot read {full}: {exc}") from exc
            files[rel] = _digest_hex(data)
            if filename in ("METADATA", "PKG-INFO", "WHEEL", "RECORD"):
                meta_raw.setdefault(filename, data)
    return files, meta_raw


# --------------------------------------------------------------------------
# manifest construction
# --------------------------------------------------------------------------


def _kind_of(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".whl") or lower.endswith(".zip"):
        return "wheel"
    if lower.endswith(".tar.gz") or lower.endswith(".tgz") or lower.endswith(".tar"):
        return "sdist"
    return "tree"


def build_manifest(path: str) -> Dict[str, Any]:
    """Build a deterministic manifest for a wheel, sdist, or directory."""
    if not os.path.exists(path):
        raise DistAuditError(f"no such artifact: {path}")
    kind = _kind_of(path)
    if os.path.isdir(path):
        files, meta_raw = _read_tree(path)
        kind = "tree"
    elif kind == "wheel":
        files, meta_raw = _read_wheel(path)
    else:
        files, meta_raw = _read_sdist(path)

    metadata: Dict[str, Any] = {}
    raw = meta_raw.get("METADATA") or meta_raw.get("PKG-INFO")
    if raw is not None:
        metadata = parse_metadata(raw.decode("utf-8", "replace"))

    return {
        "schema": MANIFEST_SCHEMA,
        "artifact": {
            "name": os.path.basename(os.path.normpath(path)),
            "kind": kind,
            "file_count": len(files),
            "tree_digest": _tree_digest(files),
        },
        "metadata": {
            "name": metadata.get("Name"),
            "version": metadata.get("Version"),
            "requires_python": metadata.get("Requires-Python"),
            "license": metadata.get("License"),
            "license_expression": metadata.get("License-Expression"),
            "requires_dist": _as_list(metadata.get("Requires-Dist")),
        },
        "files": files,
    }


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def dumps(manifest: Dict[str, Any], *, indent: int = 2) -> str:
    """Stable JSON text. File map printed sorted so diffs stay readable."""
    ordered = dict(manifest)
    ordered["files"] = {k: manifest["files"][k] for k in sorted(manifest["files"])}
    return json.dumps(ordered, indent=indent, sort_keys=True) + "\n"


def write_manifest(path: str, out_path: str) -> Dict[str, Any]:
    manifest = build_manifest(path)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(dumps(manifest))
    return manifest


# --------------------------------------------------------------------------
# drift
# --------------------------------------------------------------------------


@dataclass
class Drift:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    changed: List[str] = field(default_factory=list)
    metadata_changed: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)
    tree_changed: bool = False

    @property
    def clean(self) -> bool:
        return not (
            self.added or self.removed or self.changed or self.metadata_changed
        )

    def summary(self) -> str:
        if self.clean:
            return "no drift"
        parts = []
        if self.added:
            parts.append(f"{len(self.added)} added")
        if self.removed:
            parts.append(f"{len(self.removed)} removed")
        if self.changed:
            parts.append(f"{len(self.changed)} changed")
        if self.metadata_changed:
            parts.append(f"{len(self.metadata_changed)} metadata field(s) changed")
        return ", ".join(parts)


_WATCHED_METADATA = ("name", "version", "requires_python", "license_expression")


def diff_manifests(old: Dict[str, Any], new: Dict[str, Any]) -> Drift:
    """Compare two manifests. Nothing is inferred from names alone."""
    drift = Drift()
    old_files = old.get("files", {})
    new_files = new.get("files", {})
    for path in sorted(new_files):
        if path not in old_files:
            drift.added.append(path)
        elif old_files[path] != new_files[path]:
            drift.changed.append(path)
    for path in sorted(old_files):
        if path not in new_files:
            drift.removed.append(path)

    old_tree = (old.get("artifact") or {}).get("tree_digest")
    new_tree = (new.get("artifact") or {}).get("tree_digest")
    drift.tree_changed = bool(old_tree and new_tree and old_tree != new_tree)

    # File-map differences do not set `tree_changed`; that flag exists to make a
    # tree_digest mismatch visible when someone rebuilt a manifest by hand.
    old_meta = old.get("metadata") or {}
    new_meta = new.get("metadata") or {}
    for key in _WATCHED_METADATA:
        if old_meta.get(key) != new_meta.get(key):
            drift.metadata_changed[key] = (old_meta.get(key), new_meta.get(key))

    # Requires-Dist is a list; a reordering is not a change. Compare sorted.
    old_req = sorted(_as_list(old_meta.get("requires_dist")))
    new_req = sorted(_as_list(new_meta.get("requires_dist")))
    if old_req != new_req:
        drift.metadata_changed["requires_dist"] = (old_req, new_req)
    return drift


# --------------------------------------------------------------------------
# leak scan
# --------------------------------------------------------------------------


def find_risky_paths(manifest: Dict[str, Any]) -> List[str]:
    """Paths whose *name* suggests a credential or env file.

    This is a name check. It cannot see the contents, and it will not catch a
    secret inside `settings.py`. Say so wherever the result is reported.
    """
    hits = []
    for path in sorted(manifest.get("files", {})):
        lower = path.lower()
        base = lower.rsplit("/", 1)[-1]
        if base == ".env" or base.startswith(".env."):
            hits.append(path)
            continue
        for marker in RISKY_PATH_MARKERS:
            if lower.endswith(marker) or marker in lower:
                hits.append(path)
                break
    return hits


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------


def _signing_bytes(manifest: Dict[str, Any]) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return _canonical_json(payload)


def sign(manifest: Dict[str, Any], key: bytes) -> Dict[str, Any]:
    """Return a copy of `manifest` with an HMAC-SHA256 signature attached.

    HMAC proves the manifest was produced by a holder of the key. It does NOT
    prove the artifact on disk is the one the signer saw, and it does NOT
    replace a detached signature from a public-key system. Its purpose is to
    catch tampering in transit and accidental hand-edits.
    """
    if not key:
        raise DistAuditError("refusing to sign with an empty key")
    signed = dict(manifest)
    signed.pop("signature", None)
    digest = hmac.new(key, _signing_bytes(signed), hashlib.sha256).digest()
    signed["signature"] = {
        "scheme": "hmac-sha256",
        "value": base64.b64encode(digest).decode("ascii"),
    }
    return signed


def verify(manifest: Dict[str, Any], key: bytes) -> bool:
    """True when the attached signature matches `key` over the current body."""
    sig = (manifest or {}).get("signature") or {}
    if sig.get("scheme") != "hmac-sha256" or not sig.get("value"):
        return False
    body = {k: v for k, v in manifest.items() if k != "signature"}
    expected = hmac.new(key, _signing_bytes(body), hashlib.sha256).digest()
    try:
        given = base64.b64decode(sig["value"], validate=True)
    except Exception:
        return False
    return hmac.compare_digest(expected, given)


# --------------------------------------------------------------------------
# verdicts
# --------------------------------------------------------------------------


def _severity_of(drift: Drift, risky: Iterable[str]) -> Tuple[str, List[str]]:
    """Map observed evidence to one severity. Worst finding wins."""
    reasons: List[str] = []
    severity = "info"
    def bump(level: str) -> None:
        nonlocal severity
        if _ORDER[level] > _ORDER[severity]:
            severity = level

    if drift.removed:
        bump("high")
        reasons.append(f"{len(drift.removed)} file(s) disappeared since the baseline")
    if drift.changed:
        bump("high")
        reasons.append(f"{len(drift.changed)} file(s) changed since the baseline")
    if drift.added:
        bump("medium")
        reasons.append(f"{len(drift.added)} file(s) appeared since the baseline")
    risky_list = list(risky)
    if risky_list:
        bump("high")
        reasons.append(f"{len(risky_list)} path(s) look like credentials or env files")
    for key, (old, new) in drift.metadata_changed.items():
        bump("low")
        reasons.append(f"metadata '{key}' changed: {old!r} -> {new!r}")
    if severity == "info" and drift.tree_changed:
        bump("low")
        reasons.append("tree digest changed")
    return severity, reasons


def check(
    artifact_path: str,
    baseline: Optional[Dict[str, Any]] = None,
    *,
    key: Optional[bytes] = None,
    fail_on: str = "high",
) -> Dict[str, Any]:
    """Run the full check and return a report dict.

    Exit-code policy lives in `main()`; this function never exits.
    """
    manifest = build_manifest(artifact_path)
    drift = Drift()
    signature_state = "unsigned"
    if baseline is not None:
        if key is not None and (baseline.get("signature") or {}).get("scheme"):
            signature_state = "valid" if verify(baseline, key) else "INVALID"
        elif (baseline.get("signature") or {}).get("scheme"):
            signature_state = "unverified-no-key"
        drift = diff_manifests(baseline, manifest)
    risky = find_risky_paths(manifest)
    severity, reasons = _severity_of(drift, risky)
    if signature_state == "INVALID":
        severity = "critical"
        reasons.insert(0, "baseline signature does not verify with the supplied key")

    failed = _ORDER[severity] >= _ORDER.get(fail_on, _ORDER["high"])
    return {
        "schema": MANIFEST_SCHEMA,
        "manifest": manifest,
        "drift": {
            "clean": drift.clean,
            "added": drift.added,
            "removed": drift.removed,
            "changed": drift.changed,
            "metadata_changed": {
                k: list(v) for k, v in drift.metadata_changed.items()
            },
            "tree_changed": drift.tree_changed,
            "summary": drift.summary(),
        },
        "risky_paths": risky,
        "signature": signature_state,
        "severity": severity,
        "reasons": reasons,
        "fail_on": fail_on,
        "failed": failed,
    }


def render_text(report: Dict[str, Any]) -> str:
    manifest = report["manifest"]
    art = manifest["artifact"]
    lines = [
        f"artifact : {art['name']} ({art['kind']}, {art['file_count']} files)",
        f"tree     : {art['tree_digest'][:16]}",
        f"name/ver : {manifest['metadata'].get('name')} "
        f"{manifest['metadata'].get('version')}",
        f"drift    : {report['drift']['summary']}",
        f"signature: {report['signature']}",
        f"severity : {report['severity']} (fail-on {report['fail_on']})",
    ]
    for path in report["drift"]["removed"][:10]:
        lines.append(f"  - removed {path}")
    for path in report["drift"]["changed"][:10]:
        lines.append(f"  ~ changed {path}")
    for path in report["drift"]["added"][:10]:
        lines.append(f"  + added   {path}")
    for reason in report["reasons"]:
        lines.append(f"  ! {reason}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _usage() -> str:
    return (
        "tiny-dist-audit 0.1.0\n"
        "\n"
        "usage:\n"
        "  tiny-dist-audit manifest ARTIFACT [-o OUT.json]\n"
        "  tiny-dist-audit check ARTIFACT [--baseline B.json] [--key-env VAR]\n"
        "                                  [--fail-on info|low|medium|high|critical]\n"
        "  tiny-dist-audit diff OLD.json NEW.json\n"
        "  tiny-dist-audit tree-digest ARTIFACT\n"
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys_argv(argv))
    if not args or args[0] in ("-h", "--help", "help"):
        print(_usage())
        return 0
    command, rest = args[0], args[1:]

    def opt(name: str, default: Optional[str] = None) -> Optional[str]:
        if name in rest:
            idx = rest.index(name)
            if idx + 1 >= len(rest):
                raise SystemExit(f"{name} needs a value")
            return rest[idx + 1]
        return default

    try:
        if command == "manifest":
            target = _first_positional(rest)
            if not target:
                print(_usage())
                return 2
            out = opt("-o", "-")
            manifest = build_manifest(target)
            text = dumps(manifest)
            if out == "-":
                print(text, end="")
            else:
                with open(out, "w", encoding="utf-8") as handle:
                    handle.write(text)
            return 0

        if command == "tree-digest":
            target = _first_positional(rest)
            if not target:
                print(_usage())
                return 2
            print(build_manifest(target)["artifact"]["tree_digest"])
            return 0

        if command == "diff":
            positions = _positionals(rest)
            if len(positions) < 2:
                print(_usage())
                return 2
            with open(positions[0], encoding="utf-8") as handle:
                old = json.load(handle)
            with open(positions[1], encoding="utf-8") as handle:
                new = json.load(handle)
            drift = diff_manifests(old, new)
            print(drift.summary())
            for path in drift.added:
                print(f"  + {path}")
            for path in drift.removed:
                print(f"  - {path}")
            for path in drift.changed:
                print(f"  ~ {path}")
            for key, (before, after) in drift.metadata_changed.items():
                print(f"  ! {key}: {before!r} -> {after!r}")
            return 0 if drift.clean else 4

        if command == "check":
            target = _first_positional(rest)
            if not target:
                print(_usage())
                return 2
            baseline = None
            baseline_path = opt("--baseline")
            if baseline_path:
                with open(baseline_path, encoding="utf-8") as handle:
                    baseline = json.load(handle)
            key = None
            key_env = opt("--key-env")
            if key_env:
                raw = os.environ.get(key_env)
                if raw is None:
                    print(f"environment variable {key_env} is not set", flush=True)
                    return 2
                key = raw.encode("utf-8")
            fail_on = opt("--fail-on", "high") or "high"
            if fail_on not in _ORDER:
                print(f"unknown --fail-on level: {fail_on}")
                return 2
            report = check(target, baseline, key=key, fail_on=fail_on)
            print(render_text(report))
            return 5 if report["failed"] else 0

        print(f"unknown command: {command}")
        print(_usage())
        return 2
    except DistAuditError as exc:
        print(f"error: {exc}")
        return 2


def sys_argv(argv: Optional[List[str]]) -> List[str]:
    """Indirection so tests never touch the real process argv."""
    return list(sys.argv[1:] if argv is None else argv)


def _positionals(args: List[str]) -> List[str]:
    out: List[str] = []
    skip = False
    valued = {"-o", "--baseline", "--key-env", "--fail-on"}
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in valued:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        out.append(arg)
    return out


def _first_positional(args: List[str]) -> Optional[str]:
    found = _positionals(args)
    return found[0] if found else None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
