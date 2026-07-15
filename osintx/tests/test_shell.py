from utils.shell import CommandResult, is_tool_available, run_command


def test_run_command_basic_echo():
    result = run_command(["echo", "hello"], timeout=5)
    assert result.ok
    assert "hello" in result.stdout


def test_run_command_never_uses_shell_injection():
    # Passing a shell metacharacter as a literal argv element must NOT be
    # interpreted by a shell — it should just be echoed back verbatim.
    result = run_command(["echo", "hello; rm -rf /tmp/should_not_exist"], timeout=5)
    assert result.ok
    assert "hello; rm -rf /tmp/should_not_exist" in result.stdout


def test_run_command_missing_executable_returns_127():
    result = run_command(["this-binary-does-not-exist-xyz"], timeout=5)
    assert result.returncode == 127
    assert not result.ok


def test_run_command_timeout():
    result = run_command(["sleep", "5"], timeout=1)
    assert result.timed_out
    assert not result.ok


def test_is_tool_available_for_known_binary():
    assert is_tool_available("echo") is True


def test_is_tool_available_for_unknown_binary():
    assert is_tool_available("definitely-not-a-real-tool-xyz") is False
