# ADR-0002 — isolated Chromium with a stdio gateway

Status: ACCEPTED for fixture testing only, 2026-11-05.

The original Spec Kit plan proposed a Unix-domain socket. Docker Desktop
bind-mounts of host sockets are platform-sensitive and introduce permissions
issues. We use process stdin/stdout instead. The no-network browser sends
bounded JSON fetch requests. Only a trusted Python gateway session on the
host can authorize an exact domain and return bounded response data.

All browser HTTP resource requests are intercepted. The browser has no
route.continue() call and no container network path. The host broker checks
HMAC-signed, tenant-bound grants and shared caps before serving responses.
Raw response data and URL parameters are not retained in scan reports.

This is a **fixture-only** simulator with an .invalid origin and fake DNS/HTTP.
The host running this simulator is NOT a production isolated egress gateway.
Live scans require a separate firewall-restricted egress runtime (EG-003).
