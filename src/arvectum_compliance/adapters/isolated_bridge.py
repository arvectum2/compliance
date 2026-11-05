"""No-network Chromium ↔ nftables-protected gateway through host process pipes."""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from pathlib import Path

from arvectum_compliance.adapters.browser_fixture import (
    parse_fixture_json,
    parse_owned_internal_json,
)

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = frozenset(("consent.html", "attack.html", "inconclusive.html"))


class _BoundedLines:
    """Bounded, timeout-safe pipe framing; partial lines never block readline()."""

    def __init__(self, proc: subprocess.Popen) -> None:
        if proc.stdout is None:
            raise RuntimeError("Missing container stdout")
        self._proc = proc
        self._buffer = bytearray()
        self._selector = selectors.DefaultSelector()
        self._selector.register(proc.stdout, selectors.EVENT_READ)

    def next(self, deadline: float, limit: int) -> bytes:
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = bytes(self._buffer[:index + 1])
                del self._buffer[:index + 1]
                if len(line) > limit:
                    raise ValueError("IPC line exceeds limit")
                return line
            if len(self._buffer) > limit:
                raise ValueError("Partial IPC line exceeds limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._selector.select(remaining):
                raise TimeoutError("Isolated container IPC timeout")
            data = os.read(self._proc.stdout.fileno(), min(65536, limit + 1))
            if not data:
                raise RuntimeError("Container stdout ended without IPC line")
            self._buffer.extend(data)

    def close(self) -> None:
        self._selector.close()


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=3)
    for pipe in (proc.stdin, proc.stdout):
        if pipe:
            pipe.close()


def _run_isolated(fixture: str, *, timeout_s: int = 70):
    """No-network browser with kernel-filtered gateway, no public API."""
    if fixture not in (FIXTURES | {"internal-owned"}) or not 15 <= timeout_s <= 90:
        raise ValueError("Unapproved fixture or timeout")
    deadline = time.monotonic() + timeout_s
    gateway_args = ["internal-owned"] if fixture == "internal-owned" else ["fixture", fixture]
    gateway = subprocess.Popen(
        [str(ROOT / "scripts/run-egress-stdio-gateway.sh"), *gateway_args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    browser = None
    br_lines = None
    gw_lines = _BoundedLines(gateway)
    try:
        if gw_lines.next(deadline, 100) != b"FIREWALL_APPLIED\n":
            raise RuntimeError("Kernel firewall not initialized")
        browser = subprocess.Popen(
            [str(ROOT / "scripts/run-browser-bridge-fixture.sh"), fixture],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        br_lines = _BoundedLines(browser)
        seen = 0
        while time.monotonic() < deadline:
            msg = json.loads(br_lines.next(deadline, 80_000))
            if not isinstance(msg, dict) or "kind" not in msg:
                raise ValueError("Invalid browser IPC")
            if msg["kind"] == "fetch":
                seen += 1
                if (
                    seen > 120 or set(msg) != {
                        "kind", "id", "url", "method", "resource_type"
                    } or type(msg.get("id")) is not int or msg["id"] != seen
                ):
                    raise ValueError("Replayed/invalid browser IPC")
                assert gateway.stdin and browser.stdin
                gateway.stdin.write(
                    (json.dumps(msg, separators=(",", ":")) + "\n").encode(),
                )
                gateway.stdin.flush()
                reply = gw_lines.next(deadline, 1_600_000)
                parsed = json.loads(reply)
                if (
                    not isinstance(parsed, dict)
                    or parsed.get("kind") != "reply"
                    or parsed.get("id") != seen
                    or type(parsed.get("allowed")) is not bool
                ):
                    raise ValueError("Invalid gateway reply")
                browser.stdin.write(reply)
                browser.stdin.flush()
            elif msg["kind"] == "result":
                if set(msg) != {"kind", "report"}:
                    raise ValueError("Unexpected result envelope")
                raw = msg["report"]
                if not isinstance(raw, dict) or raw.get("fixture") != fixture:
                    raise ValueError("Invalid fixture identity")
                report_json = json.dumps(raw)
                result = (
                    parse_owned_internal_json(report_json)
                    if fixture == "internal-owned"
                    else parse_fixture_json(report_json)
                )
                if gateway.poll() not in (None, 0):
                    raise RuntimeError("Isolated gateway exited abnormally")
                return result
            else:
                raise RuntimeError("Browser failed without approved result")
        raise TimeoutError("Browser exceeded wall-clock deadline")
    finally:
        if br_lines:
            br_lines.close()
        gw_lines.close()
        if browser:
            _stop(browser)
        _stop(gateway)



def run_isolated_fixture(fixture: str, *, timeout_s: int = 70):
    if fixture not in FIXTURES:
        raise ValueError("Only approved synthetic fixture accepted")
    return _run_isolated(fixture, timeout_s=timeout_s)


def run_isolated_owned(*, timeout_s: int = 70):
    """Explicit internal own-site smoke; never a proof of DNS verification."""
    return _run_isolated("internal-owned", timeout_s=timeout_s)
