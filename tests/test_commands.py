"""Unit tests for the command parser."""

from __future__ import annotations

import pytest

from permission_guard.commands import CommandParseError, Operator, Segment, parse_command


def argvs(raw: str) -> list[list[str]]:
    return [s.argv for s in parse_command(raw).segments]


def ops(raw: str) -> list[str]:
    return [o.text for o in parse_command(raw).operators]


def test_simple_command():
    assert argvs("ls -la sub") == [["ls", "-la", "sub"]]
    assert ops("ls -la sub") == []


def test_quotes_group_words_and_hide_operators():
    parsed = parse_command("echo 'a | b' \"c && d\"")
    assert parsed.segments == [Segment(["echo", "a | b", "c && d"])]
    assert parsed.operators == []


def test_escaped_operator_is_literal():
    assert argvs(r"echo a\|b") == [["echo", "a|b"]]
    assert ops(r"echo a\|b") == []


def test_obfuscated_program_name_is_normalised():
    assert argvs("r''m -rf /") == [["rm", "-rf", "/"]]
    assert argvs(r"\rm -rf /") == [["rm", "-rf", "/"]]
    assert argvs('"r"m -rf /') == [["rm", "-rf", "/"]]


@pytest.mark.parametrize(
    "raw, expected_ops",
    [
        ("ls | wc -l", ["|"]),
        ("ls && pwd", ["&&"]),
        ("ls; pwd", [";"]),
        ("ls || pwd", ["||"]),
        ("echo x > out", [">"]),
        ("echo x >> out", [">>"]),
        ("cat < in", ["<"]),
        ("ls 2>&1", [">&"]),
        ("ls\npwd", ["\\n"]),
        ("ls &", ["&"]),
        ("(ls)", ["(", ")"]),
    ],
)
def test_operators_are_detected(raw, expected_ops):
    assert ops(raw) == expected_ops


def test_pieces_keep_order():
    parsed = parse_command("a b | c d")
    assert parsed.pieces == [Segment(["a", "b"]), Operator("|"), Segment(["c", "d"])]


@pytest.mark.parametrize(
    "raw, flagged",
    [
        ("echo $(id)", True),
        ("echo `id`", True),
        ('echo "$(id)"', True),
        ('echo "`id`"', True),
        ("echo '$(id)'", False),   # single quotes are literal
        ("echo '`id`'", False),
        ("echo \\$(id)", False),   # escaped dollar
        ("echo $HOME", False),
    ],
)
def test_command_substitution_detection(raw, flagged):
    assert parse_command(raw).has_substitution is flagged


@pytest.mark.parametrize("raw", ["echo 'open", 'echo "open', "echo trailing\\"])
def test_unparseable_commands_raise(raw):
    with pytest.raises(CommandParseError):
        parse_command(raw)
