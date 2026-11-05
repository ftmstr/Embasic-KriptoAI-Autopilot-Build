"""Deterministic *synthetic-only* in-memory ZIP + SHA-256 receipts.

No filesystem access, real data, trading, model research or deployment.
A checksum is not an authentication signature or a rollback authorization.
The expected manifest digest and commit IDs must come from a trusted source.
"""
import hashlib
import hmac
import io
import json
import re
import zipfile

MAX_ENTRIES = 32
MAX_MEMBER = 131072
MAX_TOTAL = 524288
MAX_ARCHIVE = 589824
MAX_MANIFEST = 16384
FORMAT = "SYNTHETIC-SNAPSHOT-V1"
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
FILE_ATTR = 0o100644 << 16
TOP_KEYS = {"format", "source_commit", "rollback_commit", "entries",
            "archive_sha256", "live_trading_allowed", "scientifically_validated"}
ENTRY_KEYS = {"path", "size", "sha256"}


class SnapshotRejected(ValueError):
    """Fail-closed rejection of an untrusted toy bundle."""


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _is_hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _path_ok(path):
    if type(path) is not str or not path.isascii() or not (1 <= len(path) <= 96):
        return False
    if path in ("README.md", "PUBLICATION_GATE.md"):
        return True
    if not path.startswith("safe_public_ci/"):
        return False
    name = path[len("safe_public_ci/"):]
    return bool(re.fullmatch(r"[a-z][a-z0-9_]*\.py", name))


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotRejected("duplicate JSON key")
        result[key] = value
    return result


def _no_constants(_):
    raise SnapshotRejected("nonfinite JSON number")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _check_source(files, source_commit, rollback_commit):
    if not _is_hex(source_commit, HEX40) or not _is_hex(rollback_commit, HEX40):
        raise SnapshotRejected("untrusted or malformed Git source/rollback commitment")
    if type(files) is not dict or not 1 <= len(files) <= MAX_ENTRIES:
        raise SnapshotRejected("invalid synthetic-only source count")
    seen = set()
    total = 0
    for path, data in files.items():
        if not _path_ok(path) or path.casefold() in seen:
            raise SnapshotRejected("non-allowlisted/duplicate source path")
        seen.add(path.casefold())
        if type(data) is not bytes or not 1 <= len(data) <= MAX_MEMBER:
            raise SnapshotRejected("invalid source bytes")
        total += len(data)
        if total > MAX_TOTAL:
            raise SnapshotRejected("oversized source bytes")


def build_synthetic_snapshot(files, *, source_commit, rollback_commit):
    """Build canonical in-memory ZIP and manifest; no release or model approval."""
    _check_source(files, source_commit, rollback_commit)
    buf = io.BytesIO()
    rows = []
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as z:
        for path in sorted(files):
            data = files[path]
            info = zipfile.ZipInfo(path, date_time=FIXED_DATE)
            info.create_system = 3
            info.external_attr = FILE_ATTR
            info.compress_type = zipfile.ZIP_STORED
            z.writestr(info, data)
            rows.append({"path": path, "size": len(data), "sha256": _digest(data)})
    archive = buf.getvalue()
    if len(archive) > MAX_ARCHIVE:
        raise SnapshotRejected("oversized ZIP output")
    manifest = _canonical({
        "format": FORMAT,
        "source_commit": source_commit,
        "rollback_commit": rollback_commit,
        "entries": rows,
        "archive_sha256": _digest(archive),
        "live_trading_allowed": False,
        "scientifically_validated": False,
    })
    if len(manifest) > MAX_MANIFEST:
        raise SnapshotRejected("oversized manifest")
    return archive, manifest


def verify_synthetic_snapshot(archive, manifest, *, trusted_manifest_sha256,
                              trusted_source_commit, trusted_rollback_commit):
    """Strict read-only check using out-of-band trusted expected values."""
    if (type(archive) is not bytes or not 1 <= len(archive) <= MAX_ARCHIVE or
            type(manifest) is not bytes or not 1 <= len(manifest) <= MAX_MANIFEST or
            not _is_hex(trusted_manifest_sha256, HEX64) or
            not _is_hex(trusted_source_commit, HEX40) or
            not _is_hex(trusted_rollback_commit, HEX40)):
        raise SnapshotRejected("invalid external trust input or package bytes")
    if not hmac.compare_digest(_digest(manifest), trusted_manifest_sha256):
        raise SnapshotRejected("external manifest mismatch")
    try:
        data = json.loads(manifest.decode("ascii"), object_pairs_hook=_pairs_unique,
                          parse_constant=_no_constants)
        if _canonical(data) != manifest:
            raise SnapshotRejected("noncanonical manifest")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise SnapshotRejected("malformed manifest") from exc
    if (type(data) is not dict or set(data) != TOP_KEYS or
            data["format"] != FORMAT or
            data["source_commit"] != trusted_source_commit or
            data["rollback_commit"] != trusted_rollback_commit or
            data["live_trading_allowed"] is not False or
            data["scientifically_validated"] is not False or
            not _is_hex(data["archive_sha256"], HEX64) or
            not hmac.compare_digest(_digest(archive), data["archive_sha256"])):
        raise SnapshotRejected("invalid package identity or safety status")
    rows = data["entries"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ENTRIES:
        raise SnapshotRejected("invalid entry list")
    previous = ""
    total = 0
    for row in rows:
        if (type(row) is not dict or set(row) != ENTRY_KEYS or
                not _path_ok(row["path"]) or row["path"] <= previous or
                type(row["size"]) is not int or not 1 <= row["size"] <= MAX_MEMBER or
                not _is_hex(row["sha256"], HEX64)):
            raise SnapshotRejected("invalid entry declaration")
        total += row["size"]
        if total > MAX_TOTAL:
            raise SnapshotRejected("oversized member total")
        previous = row["path"]
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as z:
            infos = z.infolist()
            if len(infos) != len(rows) or z.comment:
                raise SnapshotRejected("unexpected ZIP members or comments")
            for info, row in zip(infos, rows):
                if (info.filename != row["path"] or info.file_size != row["size"] or
                        info.compress_size != row["size"] or
                        info.compress_type != zipfile.ZIP_STORED or
                        info.date_time != FIXED_DATE or
                        info.external_attr != FILE_ATTR or
                        info.extra or info.comment or info.flag_bits & 1):
                    raise SnapshotRejected("noncanonical or unsafe ZIP member")
                payload = z.read(info)
                if len(payload) != row["size"] or not hmac.compare_digest(
                        _digest(payload), row["sha256"]):
                    raise SnapshotRejected("member content mismatch")
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError, NotImplementedError,
            ValueError) as exc:
        raise SnapshotRejected("invalid or modified ZIP") from exc
    return True
