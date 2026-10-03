from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_compose_mount_access_and_selinux_labels():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    service = compose["services"]["cerberus-ti"]
    mounts = {}
    for mount in service["volumes"]:
        source, target, *mode = mount.split(":")
        options = set(mode[0].split(",")) if mode else {"rw"}
        mounts[target] = (source, options)
        if source.startswith((".", "/")):
            assert "Z" in options, f"Dedicated bind mount {source} needs private relabeling"

    assert mounts["/app/config.yaml"] == ("./config.yaml", {"ro", "Z"})
    data_source, data_options = mounts["/data"]
    assert data_source == "cerberus-data"
    assert data_source in compose["volumes"]
    assert "rw" in data_options and "ro" not in data_options
    assert service["environment"]["CERBERUS_DATABASE_URL"] == "sqlite:////data/cerberus.db"


def test_deployment_preserves_non_root_security():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    service = compose["services"]["cerberus-ti"]
    assert "USER 10001:10001" in (ROOT / "Dockerfile").read_text().splitlines()
    assert "user" not in service
    assert not service.get("privileged", False)
    assert service["read_only"] is True
    assert "ALL" in service["cap_drop"]
    assert service["security_opt"] == ["no-new-privileges:true"]
