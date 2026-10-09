"""Approval flow tests with mocked user input."""

from __future__ import annotations

from permission_guard import ActionRequest
from permission_guard.approval import AutoApprover, CliApprover


def make_approver(answers: list[str]):
    """Return a CliApprover fed from a scripted list plus the list of prompts it issued."""
    prompts: list[str] = []
    outputs: list[str] = []

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return answers.pop(0)

    approver = CliApprover(input_fn=fake_input, output_fn=outputs.append)
    return approver, prompts, outputs


REQ = ActionRequest("delete_file", "hello.txt")


def test_yes_approves_once():
    approver, prompts, _ = make_approver(["y"])
    response = approver.ask(REQ, "needs approval")
    assert response.approved is True
    assert response.scope == "once"
    assert response.approver == "user"
    assert len(prompts) == 1
    assert not approver.session_grants


def test_no_denies():
    approver, _, _ = make_approver(["n"])
    response = approver.ask(REQ, "needs approval")
    assert response.approved is False
    assert response.scope == "denied"
    assert response.approver == "user"


def test_empty_answer_denies_by_default():
    approver, _, _ = make_approver([""])
    assert approver.ask(REQ, "r").approved is False


def test_invalid_answer_reprompts():
    approver, prompts, outputs = make_approver(["maybe", "YES"])
    response = approver.ask(REQ, "r")
    assert response.approved is True
    assert len(prompts) == 2
    assert any("Please answer" in line for line in outputs)


def test_session_approval_skips_prompt_next_time():
    approver, prompts, _ = make_approver(["s"])
    first = approver.ask(REQ, "r")
    assert first.approved is True
    assert first.scope == "session"
    assert first.approver == "session"

    second = approver.ask(REQ, "r")  # no answer left in the script; must not prompt
    assert second.approved is True
    assert second.scope == "session"
    assert len(prompts) == 1


def test_session_grant_does_not_leak_to_other_targets():
    approver, prompts, _ = make_approver(["s", "n"])
    approver.ask(REQ, "r")
    other = approver.ask(ActionRequest("delete_file", "other.txt"), "r")
    assert other.approved is False
    assert len(prompts) == 2


def test_session_grant_does_not_leak_to_other_actions():
    approver, prompts, _ = make_approver(["s", "n"])
    approver.ask(REQ, "r")
    other = approver.ask(ActionRequest("write_file", "hello.txt"), "r")
    assert other.approved is False
    assert len(prompts) == 2


def test_prompt_shows_action_target_and_reason():
    approver, _, outputs = make_approver(["y"])
    approver.ask(ActionRequest("run_command", "ls -la", {"timeout": 5}), "command needs approval")
    text = "\n".join(outputs)
    assert "run_command" in text
    assert "ls -la" in text
    assert "command needs approval" in text
    assert "timeout" in text


def test_auto_approver_records_calls():
    approver = AutoApprover(approve=False)
    response = approver.ask(REQ, "r")
    assert response.approved is False
    assert approver.calls == [REQ]
