"""Bounded argv-only subprocess execution, with process-group cleanup on Linux."""
from __future__ import annotations

import os
import selectors
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Sequence


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.output_limited


def is_tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def resolve_tool_path(name: str, configured_path: str | None = None) -> str | None:
    return shutil.which(os.path.expanduser(configured_path or name))


def _stop(proc):
    try:
        if os.name == 'posix':
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass  # Already exited; still reap below.
    proc.wait()


def run_command(argv: Sequence[str], timeout: float = 30, cwd: str | None = None,
                max_output_bytes: int = 1024 * 1024) -> CommandResult:
    if isinstance(argv, (str, bytes)) or not argv or any(not isinstance(x, str) or '\0' in x for x in argv):
        raise ValueError('Command must be a nonempty list of NUL-free string arguments')
    if timeout <= 0 or max_output_bytes < 1:
        raise ValueError('Timeout and output limit must be positive')
    argv = list(argv)
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, cwd=cwd, shell=False,
                                start_new_session=os.name == 'posix')
    except FileNotFoundError:
        return CommandResult(argv, 127, '', 'Executable or working directory not found')
    except PermissionError:
        return CommandResult(argv, 126, '', 'Permission denied executing tool')
    except OSError as exc:
        return CommandResult(argv, -1, '', f'Unable to start tool ({type(exc).__name__})')
    buffers = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    timed_out = limited = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, 0)
            selector.register(proc.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(min(remaining, .1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    room = max_output_bytes - sum(map(len, buffers))
                    buffers[key.data].extend(data[:room])
                    if len(data) > room:
                        limited = True
                        break
                if limited:
                    break
            if timed_out or limited:
                _stop(proc)
            else:
                try:
                    proc.wait(timeout=max(.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _stop(proc)
    except BaseException:
        _stop(proc)
        raise  # Includes Ctrl+C; never orphan a child or suppress cancellation.
    finally:
        proc.stdout.close()
        proc.stderr.close()
    return CommandResult(argv, proc.returncode, *(bytes(b).decode('utf-8', errors='replace') for b in buffers),
                         timed_out=timed_out, output_limited=limited)
