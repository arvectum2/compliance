from __future__ import annotations

import subprocess
import sys
import time

import pytest

from arvectum_compliance.adapters.isolated_bridge import _BoundedLines


def test_reader_handles_multiple_lines_in_one_read():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import os;os.write(1,b'first\\nsecond\\n')"],
        stdout=subprocess.PIPE,
    )
    reader = _BoundedLines(proc)
    try:
        assert reader.next(time.monotonic() + 2, 100) == b"first\n"
        assert reader.next(time.monotonic() + 2, 100) == b"second\n"
    finally:
        reader.close()
        proc.wait(timeout=2)
        proc.stdout.close()


def test_reader_does_not_hang_on_partially_written_line():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import os,time;os.write(1,b'partial');time.sleep(2)"],
        stdout=subprocess.PIPE,
    )
    reader = _BoundedLines(proc)
    try:
        with pytest.raises(TimeoutError):
            reader.next(time.monotonic() + .2, 100)
    finally:
        reader.close()
        proc.kill()
        proc.wait(timeout=2)
        proc.stdout.close()


def test_reader_rejects_oversized_response():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import os;os.write(1,b'x'*101+b'\\n')"],
        stdout=subprocess.PIPE,
    )
    reader = _BoundedLines(proc)
    try:
        with pytest.raises(ValueError):
            reader.next(time.monotonic() + 2, 100)
    finally:
        reader.close()
        proc.wait(timeout=2)
        proc.stdout.close()
