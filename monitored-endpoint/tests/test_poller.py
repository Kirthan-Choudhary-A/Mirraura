import json

import poller


def test_load_previous_falls_back_on_corrupted_state(tmp_path, monkeypatch):
    state_path = tmp_path / "poller_state.json"
    state_path.write_text("{not valid json")
    monkeypatch.setattr(poller, "STATE_PATH", state_path)

    snapshot, was_valid = poller.load_previous()
    assert snapshot == {"processes": {}, "connections": {}, "files": []}
    assert was_valid is False


def test_load_previous_reports_valid_on_good_state(tmp_path, monkeypatch):
    state_path = tmp_path / "poller_state.json"
    state_path.write_text(json.dumps({"processes": {}, "connections": {}, "files": ["a"]}))
    monkeypatch.setattr(poller, "STATE_PATH", state_path)

    snapshot, was_valid = poller.load_previous()
    assert snapshot == {"processes": {}, "connections": {}, "files": ["a"]}
    assert was_valid is True


def test_main_rebaselines_without_scoring_on_corrupted_state(tmp_path, monkeypatch, capsys):
    state_path = tmp_path / "poller_state.json"
    state_path.write_text("{not valid json")
    monkeypatch.setattr(poller, "STATE_PATH", state_path)
    monkeypatch.setattr(poller, "capture_snapshot", lambda: {
        "processes": {"1": "init"}, "connections": [], "files": ["etc-file"]
    })

    poller.main()

    assert capsys.readouterr().out == ""
    assert json.loads(state_path.read_text())["files"] == ["etc-file"]
