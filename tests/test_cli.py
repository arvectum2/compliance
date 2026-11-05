from __future__ import annotations

import json

from arvectum_compliance.cli import main


def test_cli_offline(capsys) -> None:
    rc = main(["scan-html", "tests/fixtures/review.html", "--url", "https://example.com"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["schema_version"] == "1.0"
    assert len(parsed["findings"]) == 3


def test_cli_online_requires_authorization(capsys) -> None:
    assert main(["scan-url", "http://127.0.0.1/"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_cli_rejects_missing_file(capsys) -> None:
    assert main(["scan-html", "tests/fixtures/does-not-exist.html",
                 "--url", "https://example.com"]) == 2
    assert "ERROR" in capsys.readouterr().err
