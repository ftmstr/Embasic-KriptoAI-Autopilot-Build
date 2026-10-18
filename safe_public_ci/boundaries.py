"""Synthetic JSON, ZIP metadata and Parquet envelope checks. No real data/network."""
import io
import json
import math
import stat
import zipfile

class UnsafeInput(ValueError):
    pass

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeInput("duplicate JSON key")
        result[key] = value
    return result

def _bad_constant(value):
    raise UnsafeInput("nonfinite")

def validate_synthetic_json(data):
    if type(data) is not bytes or len(data) > 65536:
        raise UnsafeInput("JSON size/type")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=_bad_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise UnsafeInput("malformed JSON") from exc
    if type(obj) is not dict or set(obj) != {"kind", "records"} or obj["kind"] != "synthetic-v1":
        raise UnsafeInput("non-synthetic")
    rows = obj["records"]
    if type(rows) is not list or not 1 <= len(rows) <= 32:
        raise UnsafeInput("row count")
    previous = -1
    for row in rows:
        if type(row) is not dict or set(row) != {"index","value"}:
            raise UnsafeInput("row shape")
        i, value = row["index"], row["value"]
        if type(i) is not int or not previous < i <= 1000000:
            raise UnsafeInput("row index")
        if type(value) not in (int,float) or not math.isfinite(value) or abs(value) > 1000000:
            raise UnsafeInput("row value")
        previous = i
    return rows

def validate_zip_envelope(data):
    if type(data) is not bytes or len(data) > 131072:
        raise UnsafeInput("ZIP size/type")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            entries = zf.infolist()
            if not 1 <= len(entries) <= 16:
                raise UnsafeInput("ZIP entries")
            seen, total = set(), 0
            for entry in entries:
                name = entry.filename.replace(chr(92), "/")
                if (not name or name.startswith("/") or ":" in name or chr(0) in name or
                    ".." in name.split("/") or name in seen):
                    raise UnsafeInput("ZIP path")
                seen.add(name)
                if entry.flag_bits & 1 or stat.S_ISLNK(entry.external_attr >> 16):
                    raise UnsafeInput("ZIP member type")
                if entry.file_size < 0 or entry.compress_size < 0 or entry.file_size > 262144:
                    raise UnsafeInput("ZIP member size")
                if entry.file_size and (not entry.compress_size or entry.file_size / entry.compress_size > 50):
                    raise UnsafeInput("ZIP bomb")
                total += entry.file_size
                if total > 262144:
                    raise UnsafeInput("ZIP total")
            return {"entries": len(entries), "declared_bytes": total}
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError) as exc:
        raise UnsafeInput("malformed ZIP") from exc

def validate_parquet_envelope(data):
    """Envelope only. Not a complete Parquet parser."""
    if (type(data) is not bytes or not 12 <= len(data) <= 131072 or
        not data.startswith(b"PAR1") or not data.endswith(b"PAR1")):
        raise UnsafeInput("Parquet envelope")
    footer = int.from_bytes(data[-8:-4], "little")
    if not 4 <= footer <= len(data)-12:
        raise UnsafeInput("Parquet footer")
    return footer
