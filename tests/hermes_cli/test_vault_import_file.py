"""File imports keep secrets local and preserve browser origin binding."""
import argparse
import json
import logging
from unittest.mock import patch

import pytest

from agent.vault_store import get_vault_store
from hermes_cli.vault import register_cli, vault_command


PASSWORD = "test-only-secret-DO-NOT-OUTPUT"


def run_import(path, *options):
    parser = argparse.ArgumentParser()
    register_cli(parser)
    vault_command(parser.parse_args(["import-file", str(path), *options]))


def test_import_roundtrip_and_wrong_site_refusal(tmp_path, capsys, caplog):
    from tools import browser_vault_tool

    caplog.set_level(logging.DEBUG)
    path = tmp_path / "login.json"
    path.write_text(json.dumps({"email": "user@example.com", "password": PASSWORD}))
    path.chmod(0o600)
    run_import(path, "--origin", "https://EXAMPLE.com:443/login", "--label", "Work")
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    store = get_vault_store()
    meta = store.get_meta(result["handle"])
    assert result == {"handle": meta.id, "label": "Work", "site": "https://example.com", "identifier": "user@example.com"}
    assert store.resolve_secret(meta.id)["password"] == PASSWORD
    assert PASSWORD not in store._vault_path.read_text()
    with patch.object(browser_vault_tool, "_current_page_origin", return_value="https://evil.example"):
        response = browser_vault_tool.browser_vault_fill(meta.id)
    assert json.loads(response)["error_type"] == "origin_mismatch"
    assert PASSWORD not in captured.out + captured.err + caplog.text + response


@pytest.mark.parametrize("case", ["missing", "malformed", "world-readable", "http", "userinfo", "same-field", "overlap", "storage-error", "custom"])
def test_import_validation_and_secret_free_diagnostics(case, tmp_path, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    path = tmp_path / "login.json"
    data = {"email": "user@example.com", "password": PASSWORD}
    options = ["--origin", "https://example.com"]
    if case == "missing":
        del data["email"]
    elif case == "http":
        options = ["--origin", "http://example.com"]
    elif case == "userinfo":
        options = ["--origin", "https://user@example.com"]
    elif case == "same-field":
        options += ["--identifier-field", "password"]
    elif case == "overlap":
        data["email"] = PASSWORD
    elif case == "custom":
        data = {"user": "user@example.com", "secret": PASSWORD}
        options += ["--identifier-field", "user", "--password-field", "secret"]
    path.write_text(json.dumps(data) if case != "malformed" else '{"' + PASSWORD)
    path.chmod(0o644 if case == "world-readable" else 0o600)
    store = get_vault_store()
    if case == "storage-error":
        def fail(*args, **kwargs):
            raise RuntimeError(PASSWORD)
        monkeypatch.setattr(type(store), "add_item", fail)
    if case == "custom":
        run_import(path, *options)
        assert store.list_items()[0].identifier_type == "username"
    else:
        with pytest.raises(SystemExit) as exc:
            run_import(path, *options)
        assert exc.value.code == 1
        assert store.list_items() == []
    captured = capsys.readouterr()
    assert PASSWORD not in captured.out + captured.err + caplog.text
    if case != "custom":
        assert not captured.out
        assert "Import failed:" in captured.err
        assert "Traceback" not in captured.err
