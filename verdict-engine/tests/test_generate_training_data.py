from generate_training_data import generate_dataset, split_dataset


def test_generate_dataset_returns_requested_count():
    dataset = generate_dataset(160, seed=1)
    assert len(dataset) == 160


def test_generate_dataset_is_deterministic_given_seed():
    a = generate_dataset(160, seed=1)
    b = generate_dataset(160, seed=1)
    a_labels = [label for _, label in a]
    b_labels = [label for _, label in b]
    assert a_labels == b_labels


def test_generate_dataset_covers_both_classes():
    dataset = generate_dataset(320, seed=2)
    labels = {label for _, label in dataset}
    assert labels == {True, False}


def test_generate_dataset_rejects_too_small_n():
    try:
        generate_dataset(10, seed=1)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_generate_dataset_events_are_valid_event_objects():
    dataset = generate_dataset(160, seed=1)
    events, _ = dataset[0]
    for e in events:
        assert e.event_type in ("process_spawn", "file_write", "network_connect")
        assert e.device_id == "synthetic"


def test_split_dataset_is_stratified():
    dataset = generate_dataset(320, seed=3)
    train, test = split_dataset(dataset, test_fraction=0.2, seed=3)
    assert len(train) + len(test) == len(dataset)
    train_labels = {label for _, label in train}
    test_labels = {label for _, label in test}
    assert train_labels == {True, False}
    assert test_labels == {True, False}
