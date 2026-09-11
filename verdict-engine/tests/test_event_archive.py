from event_archive import EventArchive


def test_append_and_read_back(tmp_path):
    archive = EventArchive(tmp_path / "event_archive.jsonl")
    archive.append({"verdict_id": "v1", "events": []})
    assert archive.all() == [{"verdict_id": "v1", "events": []}]


def test_multiple_appends_preserve_order(tmp_path):
    archive = EventArchive(tmp_path / "event_archive.jsonl")
    archive.append({"verdict_id": "v1"})
    archive.append({"verdict_id": "v2"})
    assert [r["verdict_id"] for r in archive.all()] == ["v1", "v2"]


def test_malformed_line_is_skipped(tmp_path):
    path = tmp_path / "event_archive.jsonl"
    archive = EventArchive(path)
    archive.append({"verdict_id": "v1"})
    with open(path, "a") as f:
        f.write("not valid json\n")
    archive.append({"verdict_id": "v2"})

    records = archive.all()
    assert [r["verdict_id"] for r in records] == ["v1", "v2"]


def test_creates_file_if_missing(tmp_path):
    path = tmp_path / "nested" / "event_archive.jsonl"
    EventArchive(path)
    assert path.exists()
