import pytest

from configwarden.rules import secrets
from configwarden.scanner import scan
from tests.conftest import fake_secret

CASES = [
    ("Anthropic API key", fake_secret("sk-ant-api03-", 40)),
    ("OpenAI API key", fake_secret("sk-proj-", 48)),
    ("GitHub token", fake_secret("ghp_", 36)),
    ("GitHub fine-grained token", fake_secret("github_pat_", 30)),
    ("AWS access key ID", fake_secret("AKIA", 16, "ABCDEFGH23")),
    ("Hugging Face token", fake_secret("hf_", 34)),
    ("Stripe live key", fake_secret("sk_" + "live_", 24)),
    ("Private key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
]


# ids=… : nomme chaque test par son type, pour que les faux secrets
# n'apparaissent pas dans les noms de tests ni dans le cache de pytest.
@pytest.mark.parametrize(("label", "value"), CASES, ids=[label for label, _ in CASES])
def test_detects_each_secret_type(label: str, value: str) -> None:
    findings = secrets.check_text(f'API_KEY = "{value}"\n', "config.py")
    assert [f.message.split(" found")[0] for f in findings] == [label]
    assert findings[0].line == 1


def test_secret_is_never_printed_in_full() -> None:
    value = fake_secret("ghp_", 36)
    findings = secrets.check_text(value, "x.txt")
    assert value not in findings[0].message
    assert "****" in findings[0].message


def test_anthropic_key_is_not_also_reported_as_openai() -> None:
    findings = secrets.check_text(fake_secret("sk-ant-api03-", 40), "x")
    assert len(findings) == 1


@pytest.mark.parametrize(
    "text",
    [
        "API_KEY = os.environ['API_KEY']",
        "token: ${GITHUB_TOKEN}",
        "sk-short",
        "the word ghp_ alone",
    ],
)
def test_no_false_positive_on_safe_text(text: str) -> None:
    assert secrets.check_text(text, "x") == []


def test_reports_correct_line_number(tmp_path) -> None:
    (tmp_path / "app.py").write_text("a = 1\nb = 2\nkey = '" + fake_secret("ghp_", 36) + "'\n")
    result = scan(tmp_path)
    assert [(f.path, f.line) for f in result.findings] == [("app.py", 3)]
