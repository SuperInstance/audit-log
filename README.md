# Audit Log

**A Rust library for structured audit logging** — captures security-relevant events (CRUD operations, authentication, access changes) with actor attribution and metadata for compliance and forensic analysis.

## Why It Matters

Audit logs answer "who did what, when, and to what?" They're required for SOC 2, HIPAA, PCI-DSS, ISO 27001, and FedRAMP compliance. Unlike application logs (debug, info, error), audit logs are immutable, append-only records of security events that must survive system restarts and be queryable for forensic investigation.

The distinction between audit logs and application logs is critical:

| Property | Application Logs | Audit Logs |
|----------|-----------------|------------|
| Mutability | Rotated, truncated | Immutable, append-only |
| Retention | Days to weeks | Years (regulatory minimum) |
| Query pattern | Debugging, monitoring | Forensic investigation |
| Integrity | Best-effort | Tamper-evident (sequence numbers, hashing) |
| Regulatory | None | SOC 2, HIPAA, PCI-DSS, ISO 27001 |

A missing or tampered audit record is itself a security event. This crate provides the data model for a compliant audit trail: every event captures the actor (user/service), action type, affected resource, Unix timestamp, and freeform metadata. Events are sequentially numbered with monotonic IDs for **gap detection** — any gap in the sequence indicates missing or tampered records.

## How It Works

### Event Model

Each `AuditEvent` captures the five W's of a security event:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `u64` | Monotonically incrementing sequence number |
| `actor` | `String` | Who performed the action (user, service, system) |
| `action` | `AuditAction` | What type of action (Create, Read, Update, Delete, Login, Logout) |
| `resource` | `String` | What was affected (resource identifier) |
| `timestamp` | `u64` | When (Unix epoch seconds via `SystemTime::now()`) |
| `metadata` | `String` | Additional context (IP, user agent, diff summary) |

### Sequential Integrity

The `AuditTrail` maintains a `Vec<AuditEvent>` with a monotonically incrementing `next_id` counter. Each `record()` call:

1. Atomically increments `next_id` (ensuring gap-free sequence numbers)
2. Captures the current Unix timestamp via `SystemTime::now()`
3. Stores actor, action, resource, and metadata
4. Returns the event ID for correlation

**Gap detection:** An auditor queries events and checks that `event[i].id == event[i-1].id + 1` for all consecutive events. Any violation indicates tampering or data loss. This is the simplest form of **tamper-evidence** — stronger schemes use hash chains:

```
hash(event[i]) = SHA-256(event[i-1].hash || event[i].data)
```

The current implementation provides sequential gap detection; hash-chaining can be layered on top.

**Complexity:**

| Operation | Time | Space |
|-----------|------|-------|
| Record event | O(1) amortized | O(1) per event |
| Query by actor | O(N) linear scan | O(N) results |
| Full scan | O(N) | O(N) |
| Gap detection | O(N) | O(1) |

Querying by actor is O(N) because events are stored in a flat vector. Production implementations would add an inverted index (`HashMap<String, Vec<usize>>`) for O(log N) actor lookup.

### CRUD + Auth Actions

The `AuditAction` enum covers the six standard security event categories:

```
AuditAction = Create | Read | Update | Delete | Login | Logout
```

These map to the NIST SP 800-92 "Guide to Computer Security Log Management" event taxonomy:

- **Create/Read/Update/Delete** — CRUD operations on protected resources
- **Login/Logout** — Authentication session events

Extensions for specific compliance frameworks:

| Framework | Additional Actions Needed |
|-----------|--------------------------|
| PCI-DSS | `Access`, `ConfigChange`, `PrivilegeEscalation` |
| HIPAA | `PHIAccess`, `Consent`, `Disclosure` |
| SOC 2 | `Approval`, `Review`, `Exception` |

## Quick Start

```rust
// The crate provides a demo binary with inline structs.
// The deployment evaluation logic:

fn is_healthy(error_rate: f64, latency_p99_ms: u64, success_rate: f64) -> bool {
    // All three SLOs must pass for the canary to be promoted
    error_rate < 0.05 && latency_p99_ms < 500 && success_rate > 0.95
}

// Example: canary v3.0.0 at 10% traffic with healthy metrics
let healthy = is_healthy(0.02, 320, 0.98);
if healthy {
    println!("Promote: increase traffic weight to 25%");
} else {
    println!("Rollback: revert to previous version");
}
```

> **Note:** The current implementation is a demo binary with inline structs. The production version would provide a library API as shown above.

## API

*Implemented as a demo binary with inline structs:*

| Type | Fields | Description |
|------|--------|-------------|
| `AuditAction` | `Create`, `Read`, `Update`, `Delete`, `Login`, `Logout` | Six standard event types |
| `AuditEvent` | `id`, `actor`, `action`, `resource`, `timestamp`, `metadata` | Full audit record |
| `AuditTrail` | `Vec<AuditEvent>` + `next_id` | Append-only event store |

### Planned Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `record` | `(actor, action, resource, metadata) → u64` | Record event, return ID |
| `by_actor` | `(name) → Vec<&AuditEvent>` | Filter by actor |
| `events` | `() → &[AuditEvent]` | Full event scan |
| `verify_integrity` | `() → bool` | Check for sequence gaps |

## Architecture Notes

Provides the audit logging primitive for SuperInstance services. In production, the in-memory trail would be backed by an append-only store (PostgreSQL, DynamoDB, or a write-ahead log). The data model is designed to be serializable to JSON/protobuf for transport to SIEM systems (Splunk, Elastic Security, Datadog).

Within γ + η = C, the audit trail is the **conservation ledger**: every state change in the system (γ) must produce exactly one audit event (η records the effect), and the sequential integrity invariant (C) ensures the trail is complete. A gap in the sequence is a conservation violation — energy was lost, meaning a state change occurred without being recorded.

See the [architecture overview](https://github.com/casey-digennaro/audit-log/blob/main/ARCHITECTURE.md).

## References

1. NIST SP 800-92 (2006). "Guide to Computer Security Log Management." National Institute of Standards and Technology.
2. NIST SP 800-53 Rev. 5 (2020). "Security and Privacy Controls for Information Systems and Organizations." AU-2, AU-6, AU-12.
3. PCI Security Standards Council (2022). "PCI DSS v4.0." Requirement 10: "Log and Monitor All Access to System Components."
4. Kent, K. & Souppaya, M. (2006). "NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response."

## License

MIT
