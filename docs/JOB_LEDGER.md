# EG-002b1 — durable private job ledger (internal control plane)

Status: **offline-verified reference implementation**. No daemon, HTTP
endpoint, public queue, remote workers, periodic monitoring process or
multi-tenant SaaS has been deployed.

## Contract

`JobLedger` (service/job_ledger.py) stores a bounded SQLite 0600 job
queue scoped by `(tenant, job_id)`. Only a valid, unexpired, HMAC-signed
`gateway-v2` grant with a persisted **real dual-DoH** ownership proof
may be enqueued; test/legacy DNS proofs are rejected. The tenant-scoped
`VerifiedScanService.queue_scan` path first authorizes the requester.

- Maximum 100 active jobs per tenant. Repeating the same signed grant
  is idempotent. Reusing an ID with another grant is refused.
- Worker `claim` checks at most 100 invalid-proof queued jobs per call
  (configurable 1–1000) and returns None if that budget is exhausted.
  Repeated calls resume without duplicate events, bounding lock duration.
- Worker `claim` holds a SQLite `BEGIN IMMEDIATE` transaction, marks
  one FIFO job running, and returns a fresh 256-bit lease capability.
  Only its SHA-256 digest is stored.
- Recheck proof before claim; revoked/expired proof causes `denied`
  without handing a job to a worker. Lease expires in at most 30 seconds
  and never auto-retries.
- Only the exact worker + valid lease may finish. The worker-supplied
  claim hostname and proof must match the durable row; revocation
  cannot be bypassed by substituting another verified proof ID.
  Completed results
  include an integer byte count <=1MB and a SHA-256 digest, not page
  content. Failed/denied jobs store no response data. An attempt to
  complete after proof revocation transitions to `denied` and raises.
- Each transition records a timestamp and state, not HTTP traffic,
  request parameters, cookies, raw bearer tokens, signed grants,
  HTML, user data or arbitrary error texts.
- `prune(days=30, limit=500)` deletes only old terminal records and
  related event rows, in bounded batches. Retention is 1–90 days.

### Threat-model boundaries

The ledger is an internal job *accounting primitive*, **not** an
executor or network sandbox. A future trusted worker must re-validate
the signed grant and current DNS ownership before initiating egress.
The SQLite queue is single-host only; distributed execution requires
durable shared state, authenticated worker identities, atomic
cross-database revocation and operational review. Status read without a
maintenance/claim/prune pass may show stale `running` until expiry is
materialized. The 30-second worker token is not a substitute for a
shorter per-request Ed25519 network permit.

All E2E and unit tests use synthetic offline proofs; no real
arvectum.com TXT record is created or asserted.

## Acceptance

```sh
.venv/bin/pytest -q tests/test_job_ledger.py tests/test_verified_jobs.py
```

Checks cover idempotency, signed-grant tampering, fake DNS rejection,
tenant isolation, concurrent claim winner, stale leases, revoked DNS
before and during a job, forged claim proof/hostname substitution,
no token/HTML retention, restrictive file
permissions, bounded tenant queue and retention cleanup.

## EG-002b3a — offline revocation reconciliation

`reconcile_revocations(proofs=..., now=..., limit=100)` is a trusted,
explicit maintenance operation. It checks up to 1000 active queue rows
against the persisted DNS ownership registry, transitions invalid queued
or running jobs to `denied`, clears their lease digests, and writes only
a sanitized state event. Repeated sweeps are idempotent; stale workers
cannot complete a cancelled lease. This does **not** call DNS itself,
publish a job, or start a scanner.

Limitations: the bounded sweep always starts at the oldest active job;
a large healthy prefix can starve later revoked jobs. Use this only for
small single-host queues until cursor-based pagination is implemented.
Cross-SQLite transactions are not atomic; proof revocation can race
between check and update. Production workers must recheck proof and
authorization immediately before every network request; a distributed
revocation barrier and independent audit remain PUBLIC NO-GO.


### EG-002b3b1 fair reconciliation

`reconcile_revocations` persists a lexicographic cursor in the
private ledger. Bounded passes advance beyond unchanged healthy jobs,
wrap at the tail and survive restart. It is an offline maintenance
primitive, **not** an atomic cross-store revocation barrier; a future
production worker must recheck ownership before each network request.


### EG-002b3b1a durable host binding
Claim, finish and reconciliation compare the persisted job hostname
against the current tenant-scoped DNS proof hostname (not only the
proof's active status). A corrupted or substituted durable hostname
is denied, and an active lease is invalidated; three negative tests
cover these transitions. These are offline consistency checks, not
a distributed revocation barrier.


### EG-002b3b1b — snapshot hardening
Enqueue, claim, finish and reconciliation use a single SQLite read of
proof status, verification provenance, expiry and exact hostname.
This prevents an inconsistent pair of proof reads, but cannot guarantee
atomicity across the independent proof and job databases. A revoke
committed after this read may still race with an in-flight lease:
**production release remains blocked** pending a shared transactional
revocation barrier and authenticated worker implementation.

### EG-002b3b2a — bounded expiry maintenance

`expire_batch(now=..., limit=500)` materializes at most 500 expired
queued/running jobs per call and records one sanitized transition per
job. Repeated calls drain the backlog without duplicate events. All
claim, finish, queue-quota and revocation paths independently exclude
time-expired grants/leases even when old rows have not yet been
materialized. This prevents an unbounded transaction on the critical
path when a backlog has accumulated. It does **not** create cross-DB
atomic revocation, independently authenticated workers or a production
distributed queue. A deployment must run a trusted maintenance loop
and separately review expiry-event retention and operational load.


### Maintenance indexes (EG-002b3b2c)
SQLite maintains separate indexes for queued grant expiry, running
lease expiry, tenant active quotas and terminal retention. Existing
0600 ledgers receive the indexes idempotently on reopening. Offline
tests assert query plans use the expiry indexes, not a table scan.
These are single-host performance bounds, **not** distributed revocation
atomicity or a substitute for worker identity review.

### EG-002b3b2d — read-only queue integrity preflight

`JobLedger.audit_integrity(limit=1000)` runs SQLite `quick_check(1)`
and validates bounded job-state, lease-digest, lease-expiry and terminal
summary invariants without changing job rows or logging secrets. Returns
only aggregate `checked/total/anomalies/complete` counts. A caller
must treat any anomalies **or incomplete audit** as NO-GO for worker
startup; this is a diagnostic primitive, not an enforced startup gate.
For large queues, the limit is capped at 10,000; no assurance about
uninspected rows is implied. It does not establish cross-store atomicity,
worker identity, or protection against malicious local DB administrators.


### EG-002b3b2e — identity and chronology integrity checks

The bounded, read-only preflight now checks canonical exact hostname,
opaque tenant/job/proof IDs, the stored grant signature digest format,
queued jobs without stale worker identities, valid running worker IDs,
and lease/grant chronology. Synthetic offline tampering tests verify
that these conditions increase the anomaly count without disclosing
any row content. A clean count does **not** authenticate a worker,
validate the grant signature against the signing key, or guarantee
atomic revocation across independent SQLite databases.
