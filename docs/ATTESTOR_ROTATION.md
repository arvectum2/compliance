# Feature 003 — local signing-key rotation and crash recovery

Status: implemented and tested for a **single trusted host**. Not a KMS/HSM
replacement. All examples use PRIVATE operator state; do not rotate live keys
without arranging a maintenance window and secure backup.

## Trust boundaries

- Ed25519 private seeds stay in a private `0700` directory and individual
  `0600` files. Only a matching public key is mounted into the egress
  container. The browser never receives either signing key.
- The initial key pair has legacy filenames. The first explicit rotation
  creates `attestor-g-<random-128-bit-id>.key` and `.pub` files. The
  `0600` `attestor-active.json` marker points to one generation, validated
  against the key's SHA-256 fingerprint on every subsequent load.
- A `flock` shared lock is held for the complete verified-root job,
  including signature issuance, HTTPS response and proof recheck.
  Rotations require the nonblocking exclusive lock and fail if a scan
  holds it. If a job loaded a key before rotation, it must revalidate
  that generation under the shared lock before running.
- New key files are written with `O_EXCL`, exact permissions, `fsync`;
  the active marker is replaced atomically. Old private key files are
  unlinked after successful activation. Filesystem unlink does **not**
  promise secure physical erasure or backup removal.
- New public keys cannot verify signatures from the retired private key.
  Existing isolated processes are not forcibly cancelled by this code:
  the verified-root caller's shared lock prevents rotation mid-job.

## Explicit local commands

```sh
arvectum-compliance-admin --state-dir /path/to/private-state \
  attestor-info
arvectum-compliance-admin --state-dir /path/to/private-state \
  attestor-rotate --confirm-rotation
```

The command outputs only public fingerprint, public key filename and
generation. No private key material is printed. **Do not issue a rotation
without a secure backup/maintenance plan in production.**

## Crash recovery

A crash before active-marker activation may leave newly created
non-authoritative files. The loader refuses to silently fall back and
signals an incomplete rotation. An explicitly approved recovery verifies
the EXISTING trusted key pair or active manifest, cleans only
strictly recognized abandoned generation artifacts and revalidates the
active identity. It never promotes an orphan to an active signing key.

```sh
arvectum-compliance-admin --state-dir /path/to/private-state \
  attestor-recover --confirm-recovery
```

Recovery also refuses to run while a verified job holds its shared lock.
If the active pair itself is missing, corrupted or untrusted, recovery
**fails closed** and requires manual disaster recovery from an
independently verified backup. Do not reconstruct it from orphan files.

## Tests

The unit tests cover initial and repeated rotation, old signatures,
stale identities, concurrent active jobs, malformed manifest, insecure
modes, a simulated crash before atomic activation, authorized recovery
of legacy and post-commit states, and refusal to recover without a known
trusted active key. The broader Docker and kernel network E2E remain
independent.

## Remaining production requirements

External KMS/HSM, tenant-scoped centralized revocation, distributed
locks, backup/key escrow, audited dual-control rotation, cross-node
key epochs and security review are still required before public SaaS.
