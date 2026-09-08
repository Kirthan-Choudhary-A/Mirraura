import poller


def test_load_previous_falls_back_on_corrupted_state(tmp_path, monkeypatch):
    state_path = tmp_path / "poller_state.json"
    state_path.write_text("{not valid json")
    monkeypatch.setattr(poller, "STATE_PATH", state_path)

    assert poller.load_previous() == {"processes": {}, "connections": {}, "files": []}
