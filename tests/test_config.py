import pytest
from pydantic import ValidationError

from app.config import Settings, load_settings


def test_environment_overrides(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text(
        "scheduler:\n  update_interval_minutes: 60\nallowlist:\n  domains: [EXAMPLE.COM.]\n"
    )
    monkeypatch.setenv("CERBERUS_CONFIG", str(path))
    monkeypatch.setenv("CERBERUS_UPDATE_INTERVAL_MINUTES", "15")
    monkeypatch.setenv("CERBERUS_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "do-not-expose")
    settings = load_settings()
    assert settings.scheduler.update_interval_minutes == 15
    assert not settings.scheduler.enabled
    assert settings.allowlist.domains == ["example.com"]
    assert "do-not-expose" not in repr(settings)
    assert "do-not-expose" not in settings.model_dump_json()


def test_invalid_config_rejected():
    with pytest.raises(ValidationError):
        Settings(scheduler={"update_interval_minutes": 1})
    with pytest.raises(ValidationError):
        Settings(allowlist={"domains": ["https://example.com"]})
    with pytest.raises(ValidationError):
        Settings(providers={"urlhaus": {"endpoint": "http://localhost"}})
