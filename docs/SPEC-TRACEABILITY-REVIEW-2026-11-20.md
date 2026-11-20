# Requirement → task → test candidate crosswalk

Draft, 2026-11-20. Pinned source: e3091d8569db1aa9bafd02238a46495030783491. No assertion of actual acceptance or release readiness. The links are review candidates; existing specifications and task states remain unchanged. Public NO-GO remains in force.

| Feature | Requirement | Tasks | Test candidates | Review needed |
|---|---|---|---|---|
| 001 | FR-001 | T003, T005 | test_cli.py, test_adapter.py | Verify public models, schema and Python API. |
| 001 | FR-002 | T004, T006 | test_core.py | Check form metadata and redaction. |
| 001 | FR-003 | T004, T006 | test_core.py | Heuristic-only findings and limitations. |
| 001 | FR-004 | T004, T006 | test_core.py | Check every finding field and determinism. |
| 001 | FR-005 | T005, T006 | test_cli.py, test_adapter.py, test_pinned_http.py | Check no unauthorized acquisition, limits and no JS. |
| 001 | FR-006 | T005, T006 | test_adapter.py | Verify pinned public Data Platform contract. |
| 001 | FR-007 | T006 | test_core.py, test_cli.py, test_adapter.py | Review default tests for unexpected network. |
| 001 | FR-008 | T004, T005, T006 | test_core.py, test_cli.py | Verify every required limitation. |
| 001 | AT-001 | T006, T007 | test_core.py | Run positive/negative fixtures and check CI. |
| 001 | AT-002 | T005, T006 | test_cli.py, test_adapter.py | Refusal before network. |
| 001 | AT-003 | T005, T006 | test_pinned_http.py, test_adapter.py | Private/credential URLs and redirects. |
| 001 | AT-004 | T004, T006 | test_core.py | Redaction, JSON, stable sort. |
| 001 | AT-005 | T003, T005, T007 | test_adapter.py | Direct Python API independent of CLI. |
| 002 | FR-002-01 | B001a, B001b, B001c, B004 | test_browser_docker.py, test_pinned_http.py | Production B001c remains open. |
| 002 | FR-002-02 | B001a, B001c, B003, B005 | test_browser_docker.py, test_browser_evidence.py | Live ownership and authorization remain gated. |
| 002 | FR-002-03 | B003, B004 | test_browser_docker.py, test_browser_evidence.py | Distinct contexts and approved controls. |
| 002 | FR-002-04 | B002, B004 | test_browser_evidence.py, test_browser_docker.py | Output redaction and event metadata. |
| 002 | FR-002-05 | B003, B004 | test_browser_docker.py, test_browser_evidence.py | Ambiguous consent outcome. |
| 002 | FR-002-06 | B002, B004 | test_browser_evidence.py | Review required provenance and replayability. |
| 002 | AT-002-01 | B003, B004 | test_browser_docker.py | Acceptance doc records fixtures only. |
| 002 | AT-002-02 | B001b, B001c, B004 | test_browser_docker.py, test_pinned_http.py | Production subresource rebinding not proven. |
| 002 | AT-002-03 | B002, B004 | test_browser_evidence.py, test_browser_docker.py | Inspect redacted artifacts. |
| 002 | AT-002-04 | B003, B004 | test_browser_docker.py | No submit or POST on false controls. |
| 003 | FR-003-01 | EG-001a, EG-001b, EG-001d2, EG-001d4 | test_domain_proof.py, test_dns_doh.py, test_dns_quorum.py | Production ownership and auth gated. |
| 003 | FR-003-02 | EG-001c, EG-003b2a, EG-003b2b1, EG-002b1, EG-002b3 | test_domain_proof.py, test_attested_ipc.py, test_job_ledger.py | Immutable snapshot and distributed lifecycle. |
| 003 | FR-003-03 | EG-002a, EG-003a, EG-003b1, EG-005a, EG-006c | test_isolated_gateway_docker.py, test_egress_kernel_docker.py | Independent production bypass test open. |
| 003 | FR-003-04 | EG-004a, EG-004b1, EG-006a, EG-003b2c4 | test_pinned_http.py, test_attested_ipc.py | All protocol, port, IP and TLS gates. |
| 003 | FR-003-05 | EG-004a, EG-004b1, EG-004b2, EG-005b2 | test_pinned_http.py, test_attested_ipc.py, test_resource_scope.py | Live redirects and protocol exclusions open. |
| 003 | FR-003-06 | EG-003a, EG-006c, EG-006e | test_egress_kernel_docker.py | Production independent review open. |
| 003 | FR-003-07 | EG-002a, EG-002b2, EG-002b3, EG-001d1, EG-005b2 | test_job_ledger.py, test_tenant_auth.py, test_browser_docker.py | All caps across real worker/gateway. |
| 003 | FR-003-08 | EG-002b1, EG-002b2, EG-002b3, EG-005a | test_job_ledger.py, test_browser_evidence.py | Sanitized production output. |
| 003 | FR-003-09 | EG-002b2a, EG-003b2b2, EG-006a, EG-003b2c4 | test_attested_ipc.py, test_job_ledger.py, test_dns_quorum.py | Inconclusive result, not merely transport denial. |
| 003 | AT-003-01 | EG-001a, EG-001b, EG-001c, EG-006a, EG-001d4 | test_domain_proof.py, test_attested_ipc.py | Real proof and tenant/replay/expiry scope. |
| 003 | AT-003-02 | EG-004a, EG-004b2, EG-006a, EG-006e | test_pinned_http.py, test_egress_kernel_docker.py, test_attested_ipc.py | Live DNS/subresource acceptance not proven. |
| 003 | AT-003-03 | EG-003a, EG-003b1, EG-006c, EG-006e | test_egress_kernel_docker.py, test_isolated_gateway_docker.py | Independent bypass on final configuration. |
| 003 | AT-003-04 | EG-005b1, EG-005b2, EG-007a, EG-007b | test_verified_root_docker.py, test_isolated_gateway_docker.py | Root-only pilot is not DNS-verified live consent acceptance. |
| 003 | AT-003-05 | EG-006b, EG-006d, EG-006e, EG-008b | test_egress_kernel_docker.py, test_isolated_gateway_docker.py, test_verified_root_docker.py | Reconcile exact ARM64/x86-64 evidence. |
