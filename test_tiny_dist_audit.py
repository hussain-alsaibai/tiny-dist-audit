"""Tests for tiny-dist-audit.

Every regression test here is written against a *characteristic* of the
broken behaviour, not against the line number: a fix that does not change the
observed output is not a fix.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import zipfile

import pytest

import tiny_dist_audit as tda


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _metadata(name="tiny-thing", version="1.0.0", extra=""):
    return (
        "Metadata-Version: 2.1\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        "Requires-Python: >=3.9\n"
        "License-Expression: MIT\n"
        "Requires-Dist: requests>=2\n"
        "Requires-Dist: orjson\n"
        f"{extra}"
    )


def make_wheel(path, files=None, metadata=None):
    files = files or {"tiny_thing/__init__.py": b"x = 1\n"}
    metadata = metadata or _metadata()
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        zf.writestr("tiny_thing-1.0.0.dist-info/METADATA", metadata)
        if "tiny_thing-1.0.0.dist-info/WHEEL" not in files:
            zf.writestr("tiny_thing-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
    return str(path)


def make_sdist(path, files=None, metadata=None):
    files = files or {"tiny-thing-1.0.0/tiny_thing.py": b"y = 2\n"}
    metadata = metadata or _metadata()
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        pkg = metadata.encode("utf-8")
        info = tarfile.TarInfo("tiny-thing-1.0.0/PKG-INFO")
        info.size = len(pkg)
        tf.addfile(info, io.BytesIO(pkg))
    return str(path)


TEST_KEY = b"unit-test-key"


# --------------------------------------------------------------------------
# metadata parsing
# --------------------------------------------------------------------------


def test_parse_metadata_promotes_repeated_fields_to_lists():
    meta = tda.parse_metadata(_metadata())
    assert meta["Name"] == "tiny-thing"
    assert meta["Requires-Dist"] == ["requests>=2", "orjson"]


def test_parse_metadata_single_occurrence_stays_scalar():
    """A list of length one would force every caller to handle both shapes."""
    meta = tda.parse_metadata("Name: only\nVersion: 1\n")
    assert meta["Name"] == "only"
    assert isinstance(meta["Version"], str)


def test_parse_metadata_joins_folded_continuation_lines():
    text = "Requires-Dist: big-package (>=1.0,\n    <2.0)\n"
    meta = tda.parse_metadata(text)
    assert meta["Requires-Dist"] == "big-package (>=1.0, <2.0)"


def test_parse_metadata_keeps_folded_list_entry_separate():
    text = "Requires-Dist: a\n  ==1\nRequires-Dist: b\n"
    meta = tda.parse_metadata(text)
    assert meta["Requires-Dist"] == ["a ==1", "b"]


# --------------------------------------------------------------------------
# manifests
# --------------------------------------------------------------------------


def test_wheel_manifest_records_every_entry(tmp_path):
    wheel = make_wheel(tmp_path / "t-1.0.0-py3-none-any.whl")
    manifest = tda.build_manifest(wheel)
    assert manifest["artifact"]["kind"] == "wheel"
    assert "tiny_thing/__init__.py" in manifest["files"]
    assert manifest["metadata"]["name"] == "tiny-thing"
    assert manifest["metadata"]["requires_python"] == ">=3.9"


def test_sdist_manifest_reads_pkg_info(tmp_path):
    sdist = make_sdist(tmp_path / "t-1.0.0.tar.gz")
    manifest = tda.build_manifest(sdist)
    assert manifest["artifact"]["kind"] == "sdist"
    assert manifest["metadata"]["version"] == "1.0.0"


def test_tree_manifest_skips_pycache(tmp_path):
    root = tmp_path / "pkg"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.py").write_text("a = 1\n")
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "a.cpython-311.pyc").write_bytes(b"\x00")
    manifest = tda.build_manifest(str(root))
    assert list(manifest["files"]) == ["sub/a.py"]


def test_manifest_is_byte_stable_across_rebuilds(tmp_path):
    """The whole CI story depends on this: same tree, same bytes."""
    wheel = make_wheel(tmp_path / "t-1.0.0-py3-none-any.whl")
    first = tda.dumps(tda.build_manifest(wheel))
    second = tda.dumps(tda.build_manifest(wheel))
    assert first == second


def test_tree_digest_is_order_independent():
    a = {"x/1.py": "aaa", "x/2.py": "bbb"}
    b = {"x/2.py": "bbb", "x/1.py": "aaa"}
    assert tda._tree_digest(a) == tda._tree_digest(b)


def test_tree_digest_detects_a_swapped_hash():
    a = {"x/1.py": "aaa", "x/2.py": "bbb"}
    b = {"x/1.py": "bbb", "x/2.py": "aaa"}
    assert tda._tree_digest(a) != tda._tree_digest(b)


def test_missing_artifact_is_an_error_not_an_empty_manifest():
    """An empty manifest would look like a clean audit of nothing."""
    with pytest.raises(tda.DistAuditError):
        tda.build_manifest("/nonexistent/path.whl")


def test_unreadable_wheel_raises_dist_audit_error(tmp_path):
    bogus = tmp_path / "broken.whl"
    bogus.write_bytes(b"not a zip at all")
    with pytest.raises(tda.DistAuditError):
        tda.build_manifest(str(bogus))


# --------------------------------------------------------------------------
# drift
# --------------------------------------------------------------------------


def test_identical_artifacts_have_no_drift(tmp_path):
    wheel = make_wheel(tmp_path / "t-1.0.0-py3-none-any.whl")
    baseline = tda.build_manifest(wheel)
    report = tda.check(wheel, baseline)
    assert report["drift"]["clean"] is True
    assert report["failed"] is False


def test_added_file_is_reported(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    wheel2 = make_wheel(
        tmp_path / "b.whl",
        files={"tiny_thing/__init__.py": b"x = 1\n", "tiny_thing/extra.py": b"1\n"},
    )
    report = tda.check(wheel2, baseline)
    assert report["drift"]["added"] == ["tiny_thing/extra.py"]
    assert report["severity"] == "medium"
    # added is medium and the default fail-on is high, so it must NOT fail
    assert report["failed"] is False


def test_added_file_below_fail_threshold_does_not_fail(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    wheel2 = make_wheel(
        tmp_path / "b.whl",
        files={"tiny_thing/__init__.py": b"x = 1\n", "tiny_thing/extra.py": b"1\n"},
    )
    report = tda.check(wheel2, baseline, fail_on="high")
    assert report["severity"] == "medium"
    assert report["failed"] is False
    strict = tda.check(wheel2, baseline, fail_on="medium")
    assert strict["failed"] is True


def test_changed_file_content_is_high(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    wheel2 = make_wheel(
        tmp_path / "b.whl", files={"tiny_thing/__init__.py": b"x = 2\n"}
    )
    report = tda.check(wheel2, baseline)
    assert report["drift"]["changed"] == ["tiny_thing/__init__.py"]
    assert report["severity"] == "high"
    assert report["failed"] is True


def test_removed_file_is_high(tmp_path):
    wheel = make_wheel(
        tmp_path / "a.whl",
        files={"tiny_thing/__init__.py": b"x\n", "tiny_thing/gone.py": b"g\n"},
    )
    baseline = tda.build_manifest(wheel)
    wheel2 = make_wheel(tmp_path / "b.whl", files={"tiny_thing/__init__.py": b"x\n"})
    report = tda.check(wheel2, baseline)
    assert report["drift"]["removed"] == ["tiny_thing/gone.py"]
    assert report["severity"] == "high"


def test_requires_dist_reorder_is_not_drift(tmp_path):
    """Reordering an unordered dependency set is not a release difference."""
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    reordered = _metadata().replace(
        "Requires-Dist: requests>=2\nRequires-Dist: orjson\n",
        "Requires-Dist: orjson\nRequires-Dist: requests>=2\n",
    )
    wheel2 = make_wheel(tmp_path / "b.whl", metadata=reordered)
    report = tda.check(wheel2, baseline)
    assert "requires_dist" not in report["drift"]["metadata_changed"]
    # A re-ordered METADATA line changes the file hash even though the
    # dependency set is identical. The report must show the hash change and
    # the summary must attribute it to files, not to a dependency change.
    assert "tiny_thing-1.0.0.dist-info/METADATA" in report["drift"]["changed"]
    assert report["drift"]["metadata_changed"] == {}


def test_requires_dist_addition_is_drift(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    extra = _metadata(extra="Requires-Dist: httpx\n")
    wheel2 = make_wheel(tmp_path / "b.whl", metadata=extra)
    report = tda.check(wheel2, baseline)
    assert "requires_dist" in report["drift"]["metadata_changed"]


def test_version_bump_is_metadata_drift(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    bumped = _metadata(version="1.0.1")
    wheel2 = make_wheel(
        tmp_path / "b.whl",
        files={"tiny_thing/__init__.py": b"x = 1\n"},
        metadata=bumped,
    )
    report = tda.check(wheel2, baseline)
    assert report["drift"]["metadata_changed"]["version"] == ["1.0.0", "1.0.1"]


def test_swapped_versions_with_identical_files_is_still_drift(tmp_path):
    """A repackaged wheel under a new version is exactly the case to catch."""
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    wheel2 = make_wheel(tmp_path / "b.whl", metadata=_metadata(version="9.9.9"))
    report = tda.check(wheel2, baseline)
    assert report["drift"]["clean"] is False
    assert report["drift"]["metadata_changed"]["version"] == ["1.0.0", "9.9.9"]


# --------------------------------------------------------------------------
# risky paths
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "tiny_thing/.env",
        "pkg/.env.production",
        "certs/server.pem",
        "keys/deploy.key",
        "home/.aws/credentials",
    ],
)
def test_risky_paths_are_flagged(path):
    manifest = {"files": {path: "deadbeef"}}
    assert tda.find_risky_paths(manifest) == [path]


def test_environment_py_is_not_flagged(tmp_path):
    """`environment.py` is a normal module name; `.env` is the pattern."""
    manifest = {"files": {"tiny_thing/environment.py": "x"}}
    assert tda.find_risky_paths(manifest) == []


def test_risky_path_raises_severity_to_high(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    leaky = make_wheel(
        tmp_path / "b.whl",
        files={"tiny_thing/__init__.py": b"x = 1\n", ".env": b"TOKEN=1\n"},
    )
    report = tda.check(leaky, baseline, fail_on="high")
    assert report["severity"] == "high"
    assert ".env" in report["risky_paths"]
    assert report["failed"] is True


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------


def test_sign_and_verify_roundtrip(tmp_path):
    manifest = tda.build_manifest(make_wheel(tmp_path / "a.whl"))
    signed = tda.sign(manifest, TEST_KEY)
    assert tda.verify(signed, TEST_KEY) is True


def test_verify_fails_with_wrong_key(tmp_path):
    manifest = tda.build_manifest(make_wheel(tmp_path / "a.whl"))
    signed = tda.sign(manifest, TEST_KEY)
    assert tda.verify(signed, b"other-key") is False


def test_edited_signed_manifest_fails_verification(tmp_path):
    """The attack this exists for: flip one hash, keep the signature."""
    manifest = tda.build_manifest(make_wheel(tmp_path / "a.whl"))
    signed = tda.sign(manifest, TEST_KEY)
    tampered = copy_with(signed)
    tampered["files"]["tiny_thing/__init__.py"] = "0" * 64
    assert tda.verify(tampered, TEST_KEY) is False


def test_unsigned_manifest_does_not_claim_a_valid_signature(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    baseline = tda.build_manifest(wheel)
    report = tda.check(wheel, baseline, key=TEST_KEY)
    assert report["signature"] == "unsigned"
    assert report["failed"] is False
    # Negative control: the same helper must reject a manifest with no
    # signature rather than treating "absent" as "trusted".
    assert tda.verify({}, TEST_KEY) is False
    assert tda.verify({"signature": {"scheme": "other", "value": "x"}}, TEST_KEY) is False


def test_bad_signature_is_critical_regardless_of_fail_on(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    signed = tda.sign(tda.build_manifest(wheel), TEST_KEY)
    signed["artifact"]["tree_digest"] = "f" * 64
    report = tda.check(wheel, signed, key=TEST_KEY, fail_on="critical")
    assert report["signature"] == "INVALID"
    assert report["severity"] == "critical"
    assert report["failed"] is True


def test_signed_baseline_without_key_is_unverified_not_valid(tmp_path):
    """Silence is not verification. The report must say so."""
    wheel = make_wheel(tmp_path / "a.whl")
    signed = tda.sign(tda.build_manifest(wheel), TEST_KEY)
    report = tda.check(wheel, signed)
    assert report["signature"] == "unverified-no-key"


def test_empty_key_is_refused(tmp_path):
    manifest = tda.build_manifest(make_wheel(tmp_path / "a.whl"))
    with pytest.raises(tda.DistAuditError):
        tda.sign(manifest, b"")


def copy_with(manifest):
    return json.loads(json.dumps(manifest))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_cli_manifest_writes_file(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    out = tmp_path / "m.json"
    assert tda.main(["manifest", wheel, "-o", str(out)]) == 0
    loaded = json.loads(out.read_text())
    assert loaded["schema"] == tda.MANIFEST_SCHEMA


def test_cli_check_exit_codes(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    base = tmp_path / "m.json"
    tda.main(["manifest", wheel, "-o", str(base)])
    assert tda.main(["check", wheel, "--baseline", str(base)]) == 0
    changed = make_wheel(
        tmp_path / "b.whl", files={"tiny_thing/__init__.py": b"x = 99\n"}
    )
    assert tda.main(["check", changed, "--baseline", str(base)]) == 5


def test_cli_missing_key_env_fails_loudly(tmp_path, monkeypatch):
    wheel = make_wheel(tmp_path / "a.whl")
    base = tmp_path / "m.json"
    tda.main(["manifest", wheel, "-o", str(base)])
    monkeypatch.delenv("DIST_AUDIT_TEST_KEY", raising=False)
    assert tda.main(
        ["check", wheel, "--baseline", str(base), "--key-env", "DIST_AUDIT_TEST_KEY"]
    ) == 2


def test_cli_diff_command_reports_clean(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    one, two = tmp_path / "1.json", tmp_path / "2.json"
    tda.main(["manifest", wheel, "-o", str(one)])
    tda.main(["manifest", wheel, "-o", str(two)])
    assert tda.main(["diff", str(one), str(two)]) == 0


def test_cli_unknown_command_is_usage_error():
    assert tda.main(["frobnicate"]) == 2


def test_cli_unknown_fail_on_level_is_an_error(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    assert tda.main(["check", wheel, "--fail-on", "catastrophic"]) == 2


def test_cli_tree_digest_matches_manifest(tmp_path):
    wheel = make_wheel(tmp_path / "a.whl")
    digest = tda.build_manifest(wheel)["artifact"]["tree_digest"]
    captured = io.StringIO()
    import contextlib

    with contextlib.redirect_stdout(captured):
        assert tda.main(["tree-digest", wheel]) == 0
    assert captured.getvalue().strip() == digest


def test_tree_manifest_skips_build_caches(tmp_path):
    """A cache directory is not a release artifact; it must not move the digest."""
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "a.py").write_text("a = 1\n")
    clean = tda.build_manifest(str(root))["artifact"]["tree_digest"]
    for cache in (".pytest_cache", ".mypy_cache", ".ruff_cache", ".eggs"):
        d = root / cache
        d.mkdir()
        (d / "junk").write_text("x")
    egg = root / "pkg.egg-info"
    egg.mkdir()
    (egg / "PKG-INFO").write_text("Name: pkg\n")
    assert tda.build_manifest(str(root))["artifact"]["tree_digest"] == clean


def test_bundled_example_manifest_is_loadable_and_consistent():
    """A stale example is a broken example: parse it and check its internals."""
    path = os.path.join(os.path.dirname(__file__), "examples", "dist-manifest.json")
    with open(path, encoding="utf-8") as handle:
        example = json.load(handle)
    files = example["files"]
    assert example["artifact"]["file_count"] == len(files)
    assert example["artifact"]["tree_digest"] == tda._tree_digest(files)
    assert example["schema"] == tda.MANIFEST_SCHEMA
