import pickle

import pytest

from configwarden.config import MissingSecretError, Secret, get_secret


def test_secret_is_hidden_when_printed() -> None:
    s = Secret("super-sensitive-value")
    assert "super-sensitive-value" not in repr(s)
    assert "super-sensitive-value" not in str(s)
    assert "super-sensitive-value" not in f"{s}"
    assert s.reveal() == "super-sensitive-value"


def test_secret_cannot_be_pickled() -> None:
    with pytest.raises(TypeError):
        pickle.dumps(Secret("x"))


def test_secret_equality_and_unhashable() -> None:
    assert Secret("a") == Secret("a")
    assert Secret("a") != Secret("b")
    with pytest.raises(TypeError):
        hash(Secret("a"))


def test_get_secret_reads_env_and_strips(monkeypatch) -> None:
    monkeypatch.setenv("AG_TEST_KEY", "  value-with-spaces \n")
    secret = get_secret("AG_TEST_KEY")
    assert secret is not None and secret.reveal() == "value-with-spaces"


def test_get_secret_missing(monkeypatch) -> None:
    monkeypatch.delenv("AG_TEST_KEY", raising=False)
    assert get_secret("AG_TEST_KEY") is None
    with pytest.raises(MissingSecretError, match="AG_TEST_KEY"):
        get_secret("AG_TEST_KEY", required=True)


def test_empty_value_counts_as_missing(monkeypatch) -> None:
    monkeypatch.setenv("AG_TEST_KEY", "   ")
    assert get_secret("AG_TEST_KEY") is None
