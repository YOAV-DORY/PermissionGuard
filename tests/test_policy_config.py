"""The policy file itself fails closed: bad config refuses to load."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from permission_guard import ActionRequest, Decision, Limits, PolicyConfigError, PolicyEngine
from tests.conftest import DEFAULT_POLICY


def default_config() -> dict:
    return yaml.safe_load(DEFAULT_POLICY.read_text())


def test_default_policy_loads(sandbox: Path):
    engine = PolicyEngine(default_config(), sandbox)
    assert engine.limits == Limits()


def test_limits_come_from_the_file(sandbox: Path):
    config = default_config()
    config["limits"]["max_read_bytes"] = 123
    assert PolicyEngine(config, sandbox).limits.max_read_bytes == 123


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda c: c.update(acitons={}), "unknown top-level keys"),
        (lambda c: c["actions"]["read_file"].update(inside_sandbox="maybe"), "must be one of"),
        (lambda c: c["actions"].update(format_disk={"inside_sandbox": "allow"}), "unknown action"),
        (lambda c: c["actions"]["read_file"].update(extra="x"), "may only contain"),
        (lambda c: c["limits"].update(max_read_bytes=-1), "positive integer"),
        (lambda c: c["limits"].update(max_read_bytes=True), "positive integer"),
        (lambda c: c["limits"].update(max_ram=5), "unknown limits"),
        (lambda c: c["commands"].update(unknown_program="allow"), "'deny' or 'ask'"),
        (lambda c: c["commands"].update(allowed_programs="ls"), "list of strings"),
        (lambda c: c["commands"].update(allowed_progams=["ls"]), "unknown keys in 'commands'"),
        (lambda c: c["commands"]["denied_programs"].append({"id": "x", "reason": "y"}), "missing 'names'"),
        (lambda c: c["commands"]["forbidden_options"].append({"id": "x", "reason": "y", "programs": ["a"], "oops": 1}), "unknown keys"),
        (lambda c: c["commands"].update(subcommands={"git": "status"}), "list of strings"),
    ],
)
def test_invalid_config_is_rejected(sandbox: Path, mutate, message):
    config = default_config()
    mutate(config)
    with pytest.raises(PolicyConfigError, match=message):
        PolicyEngine(config, sandbox)


@pytest.mark.parametrize("content", ["", "- just\n- a list\n", "key: [unclosed", "42"])
def test_bad_yaml_files_are_rejected(tmp_path: Path, content: str):
    (tmp_path / "policies").mkdir()
    path = tmp_path / "policies" / "bad.yaml"
    path.write_text(content)
    with pytest.raises(PolicyConfigError):
        PolicyEngine.from_yaml(path)


def test_empty_policy_denies_everything(sandbox: Path):
    engine = PolicyEngine({}, sandbox)
    for request in (
        ActionRequest("read_file", "hello.txt"),
        ActionRequest("write_file", "a.txt", {"content": "x"}),
        ActionRequest("delete_file", "hello.txt"),
        ActionRequest("run_command", "ls"),
    ):
        assert engine.evaluate(request).decision is Decision.DENY, request
