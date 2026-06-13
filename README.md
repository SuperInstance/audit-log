# Audit Log

**A Rust library for structured audit logging** — captures security-relevant events (CRUD operations, authentication, access changes) with actor attribution and metadata for compliance and forensic analysis.

## Why It Matters

Audit logs answer "who did what, when, and to what?" They're required for SOC 2, HIPAA, PCI-DSS, and ISO 27001 compliance. Unlike application logs (debug, info, error), audit logs are immutable, append-only records of security events that must survive system restarts and be queryable for investigations.

This crate provides the data model for a compliant audit trail: every event captures the actor (user/service), action type, affected resource, Unix timestamp, and freeform metadata. Events are sequentially numbered with monotonic IDs for gap detection.

## How It Works

The `AuditTrail` struct maintains a `Vec<AuditEvent>` with a monotonically incrementing `next_id` counter. Each call to `record()`:

1. Increments the internal counter (ensuring gap-free sequence numbers)
2. Captures the current Unix timestamp via `SystemTime::now()`
3. Stores the actor name, action type (`Create`, `Read`, `Update`, `Delete`, `Login`, `Logout`), resource identifier, and a metadata string
4. Returns the event ID for correlation

Querying is via `by_actor()` (filter by user/service name) or `events()` (full scan). The sequential ID design makes it trivial to detect tampering — any gap in the sequence indicates missing events.

## Quick Start

```rust
use audit_trail::{AuditTrail, AuditAction};

let mut trail = AuditTrail::new();

// Record security events
trail.record("alice", AuditAction::Login, "system", "ip=10.0.0.1");
trail.record("alice", AuditAction::Create, "document:42", "title=Q4 Report");
trail.record("bob", AuditAction::Read, "document:42", "");

// Query by actor
let alice_actions = trail.by_actor("alice");
println!("Alice performed {} actions", alice_actions.len());
```

## API

- **`AuditAction`** — Enum: `Create`, `Read`, `Update`, `Delete`, `Login`, `Logout`
- **`AuditEvent`** — Record with `id`, `actor`, `action`, `resource`, `timestamp`, `metadata`
- **`AuditTrail`** — Append-only event store
  - `record(actor, action, resource, metadata)` → event ID
  - `by_actor(name)` → `Vec<&AuditEvent>`
  - `events()` → `&[AuditEvent]`

## Architecture Notes

Provides the audit logging primitive for SuperInstance services. In production, the in-memory trail would be backed by an append-only store (e.g., PostgreSQL, DynamoDB, or a write-ahead log). The data model is designed to be serializable to JSON/protobuf for transport to SIEM systems. See the [architecture overview](https://github.com/SuperInstance/SuperInstance/blob/main/ARCHITECTURE.md).

## License

MIT
