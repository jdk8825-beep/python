from __future__ import annotations

import gzip
import json

import pytest

from cloudtrail_analyzer import load_events
from cloudtrail_analyzer.loader import LogLoadError


def record(name, time="2026-01-01T00:00:00Z"):
    return {"eventName": name, "eventTime": time}


def test_loads_records_wrapper(tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"Records": [record("A"), record("B")]}))
    assert [e.name for e in load_events([path])] == ["A", "B"]


def test_loads_gzipped_files(tmp_path):
    path = tmp_path / "a.json.gz"
    with gzip.open(path, "wt") as fh:
        json.dump({"Records": [record("A")]}, fh)
    assert [e.name for e in load_events([path])] == ["A"]


def test_loads_plain_list_and_json_lines(tmp_path):
    (tmp_path / "list.json").write_text(json.dumps([record("A")]))
    (tmp_path / "lines.jsonl").write_text(json.dumps(record("B")) + "\n\n" + json.dumps(record("C")))
    assert sorted(e.name for e in load_events([tmp_path])) == ["A", "B", "C"]


def test_directory_is_searched_recursively_and_sorted_by_time(tmp_path):
    nested = tmp_path / "AWSLogs" / "111122223333" / "CloudTrail"
    nested.mkdir(parents=True)
    (nested / "late.json").write_text(json.dumps({"Records": [record("Late", "2026-01-02T00:00:00Z")]}))
    (tmp_path / "early.json").write_text(json.dumps({"Records": [record("Early")]}))
    (tmp_path / "notes.txt").write_text("not a log")
    assert [e.name for e in load_events([tmp_path])] == ["Early", "Late"]


def test_empty_file_yields_nothing(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("")
    assert load_events([path]) == []


def test_invalid_json_raises_with_location(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"eventName": "A"}\n{oops')
    with pytest.raises(LogLoadError, match="bad.json:2"):
        load_events([path])


def test_wrong_shape_raises(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(LogLoadError, match="Records"):
        load_events([path])


def test_missing_path_raises(tmp_path):
    with pytest.raises(LogLoadError, match="no such file"):
        load_events([tmp_path / "nope.json"])
