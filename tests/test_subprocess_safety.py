import pytest
import sys
from core.utils import safe_run_subprocess


def test_safe_subprocess_invalid_command():
    # String or empty commands must be rejected
    res = safe_run_subprocess("")
    assert res is None

    res = safe_run_subprocess([])
    assert res is None


def test_safe_subprocess_missing_tool():
    # Running a nonexistent executable should report safely and return None (no unhandled exception)
    res = safe_run_subprocess(["nonexistent_tool_cyber_xyz123", "--version"])
    assert res is None


def test_safe_subprocess_timeout():
    # Python command that sleeps longer than timeout
    python_exe = sys.executable
    res = safe_run_subprocess([python_exe, "-c", "import time; time.sleep(2)"], timeout=0.5)
    assert res is None


def test_safe_subprocess_success():
    python_exe = sys.executable
    res = safe_run_subprocess([python_exe, "-c", "print('hello_cyber')"], timeout=5)
    assert res is not None
    assert "hello_cyber" in res.stdout
