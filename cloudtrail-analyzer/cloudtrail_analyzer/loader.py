"""Load CloudTrail records from files and directories.

Supported inputs:

* the format CloudTrail writes to S3: ``{"Records": [ ... ]}``, optionally gzipped
* a plain JSON list of records
* JSON Lines, one record per line (handy for logs exported from other tools)
* a directory, which is searched recursively for ``.json``, ``.jsonl`` and ``.gz`` files
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .models import Event

LOG_SUFFIXES = (".json", ".jsonl", ".json.gz", ".jsonl.gz")


class LogLoadError(Exception):
    """Raised when a file cannot be parsed as CloudTrail records."""


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def _records_from_text(text: str, path: Path) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Not a single JSON document; try JSON Lines.
        records = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise LogLoadError(f"{path}:{lineno}: invalid JSON ({exc.msg})") from exc
        return records

    if isinstance(data, dict) and isinstance(data.get("Records"), list):
        return data["Records"]
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "eventName" in data:
        return [data]
    raise LogLoadError(f"{path}: expected a CloudTrail 'Records' list")


def iter_log_files(path: Path) -> Iterator[Path]:
    """Yield log files under ``path`` (or ``path`` itself), in a stable order."""
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.name.endswith(LOG_SUFFIXES):
                yield child
    elif path.is_file():
        yield path
    else:
        raise LogLoadError(f"{path}: no such file or directory")


def load_events(paths: Iterable[str | Path]) -> list[Event]:
    """Load every record from ``paths`` and return them sorted by event time."""
    events: list[Event] = []
    for raw_path in paths:
        for file in iter_log_files(Path(raw_path)):
            try:
                text = _read_text(file)
            except (OSError, UnicodeDecodeError) as exc:
                raise LogLoadError(f"{file}: {exc}") from exc
            for record in _records_from_text(text, file):
                if isinstance(record, dict):
                    events.append(Event(record))
    events.sort(key=lambda e: e.raw.get("eventTime", ""))
    return events
