---
name: device-lifecycle-prod-fix
overview: Audit current implementation against the required production lifecycle model and execute a minimal-drift migration to DB-first, versioned, non-blocking device lifecycle operations.
todos:
  - id: audit-baseline
    content: "Lock baseline: document implemented vs missing behaviors with concrete file-level evidence for lifecycle, presence, Redis, and MQTT."
    status: pending
  - id: fix-timestamp-safety
    content: Add normalize_timestamp utility and patch presence/offline paths to eliminate float .timestamp misuse and probe crash loop.
    status: pending
  - id: add-lifecycle-version-schema
    content: Introduce DB lifecycle state + device version fields via additive migrations and transition helpers.
    status: pending
  - id: refactor-unbind-reset-async
    content: Convert unbind/reset to post-commit, non-blocking orchestration with queued background side effects and strict failure semantics.
    status: pending
  - id: add-redis-mqtt-consistency
    content: Implement versioned Redis namespace and explicit MQTT unsubscribe cleanup on unbind/reset/rebind flows.
    status: pending
  - id: expand-tests-and-smoke
    content: Add acceptance and regression tests for unbind/reset/rebind consistency, latency, and resilience; run smoke and contract suites.
    status: pending
isProject: false
---

# Croc Sentinel Production Lifecycle Fix Plan

## Current State (Implemented)
- Unbind/reset job ledger exists via `device_unbind_jobs` with staged states in [E:/Croc Sentinel/croc_sentinel_systems/api/schema.py](E:/Croc Sentinel/croc_sentinel_systems/api/schema.py) and flow in [E:/Croc Sentinel/croc_sentinel_systems/api/routers/device_delete.py](E:/Croc Sentinel/croc_sentinel_systems/api/routers/device_delete.py).
- Scheduler compensation retry exists in [E:/Croc Sentinel/croc_sentinel_systems/api/scheduler.py](E:/Croc Sentinel/croc_sentinel_systems/api/scheduler.py).
- Redis bridge has degrade-to-memory behavior in [E:/Croc Sentinel/croc_sentinel_systems/api/redis_bridge.py](E:/Croc Sentinel/croc_sentinel_systems/api/redis_bridge.py).
- Device API contract tests exist (e.g., [E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_unbind_reset_contract.py](E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_unbind_reset_contract.py), [E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_spa_api_contract.py](E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_spa_api_contract.py)).

## Gap Summary (Not Yet Implemented)
- No unified DB lifecycle enum `ACTIVE/UNBOUND/RESETTING/OFFLINE` as a single source of truth.
- No per-device lifecycle `version` increment/invalidation model for unbind/reset/rebind.
- Presence probe has a confirmed float/datetime bug in [E:/Croc Sentinel/croc_sentinel_systems/api/presence_probes.py](E:/Croc Sentinel/croc_sentinel_systems/api/presence_probes.py) (`updated.timestamp()` on float path).
- Unbind/reset request path still can synchronously wait for MQTT ACK (`_wait_cmd_ack`) in [E:/Croc Sentinel/croc_sentinel_systems/api/tenant_admin.py](E:/Croc Sentinel/croc_sentinel_systems/api/tenant_admin.py).
- No explicit MQTT unsubscribe on unbind for `device/{id}/#` and `device/{id}/cmd`.
- No Redis device namespace versioning pattern like `device:{id}:v{version}`.

## Implementation Plan (A/B/C)

### A. Safety + Stability Baseline (No behavior drift outside target)
- Add a shared `normalize_timestamp(value)` utility (likely in [E:/Croc Sentinel/croc_sentinel_systems/api/helpers.py](E:/Croc Sentinel/croc_sentinel_systems/api/helpers.py)) and replace unsafe float/datetime assumptions in presence/offline paths.
- Fix presence probe bug in [E:/Croc Sentinel/croc_sentinel_systems/api/presence_probes.py](E:/Croc Sentinel/croc_sentinel_systems/api/presence_probes.py) by removing `.timestamp()` call on float-derived values.
- Replace any tight probe retry loops with bounded exponential backoff (min 5s), keeping execution off request path.

### B. Lifecycle + Versioning Core (DB-first model)
- Introduce lifecycle columns/state transitions in schema/migrations (device-level lifecycle state + integer version).
- Define lifecycle transition helpers in one module (transaction-safe):
  - `ACTIVE -> RESETTING -> ACTIVE`
  - `ACTIVE -> UNBOUND`
  - `OFFLINE` derived/persisted policy alignment
- On unbind/reset/rebind, increment `device.version` inside DB transaction and persist audit metadata.

### C. Non-blocking Orchestration + Cache/MQTT Consistency
- Refactor unbind/reset HTTP handlers to return quickly (queued/accepted) and move MQTT/Redis side effects to background worker/scheduler pipeline.
- Enforce post-commit side effects only:
  - invalidate old cache namespaces,
  - publish completion events,
  - run MQTT unsubscribe for target device topics.
- Add Redis key helper to enforce `device:{device_id}:v{version}` namespace reads/writes and old-version cleanup.
- Ensure Redis failure degrades gracefully without repeated noisy logs (warn-once pattern).

## Verification Plan
- Extend tests for:
  - timestamp normalization + no float `.timestamp()` misuse,
  - lifecycle transition correctness and rollback semantics,
  - reset API latency (<200ms response, background completion),
  - unbind no-ghost guarantees (DB/Redis/MQTT consistency),
  - rebind version mismatch handling and single-owner invariant.
- Run target smoke suites and focused pytest modules; capture before/after latency and stability metrics for probe and reset paths.

## Key Files to Touch (Expected)
- [E:/Croc Sentinel/croc_sentinel_systems/api/helpers.py](E:/Croc Sentinel/croc_sentinel_systems/api/helpers.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/presence_probes.py](E:/Croc Sentinel/croc_sentinel_systems/api/presence_probes.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/device_presence.py](E:/Croc Sentinel/croc_sentinel_systems/api/device_presence.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/schema.py](E:/Croc Sentinel/croc_sentinel_systems/api/schema.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/schema_migrations.py](E:/Croc Sentinel/croc_sentinel_systems/api/schema_migrations.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/routers/device_delete.py](E:/Croc Sentinel/croc_sentinel_systems/api/routers/device_delete.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/tenant_admin.py](E:/Croc Sentinel/croc_sentinel_systems/api/tenant_admin.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/scheduler.py](E:/Croc Sentinel/croc_sentinel_systems/api/scheduler.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/redis_bridge.py](E:/Croc Sentinel/croc_sentinel_systems/api/redis_bridge.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_unbind_reset_contract.py](E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_unbind_reset_contract.py)
- [E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_spa_api_contract.py](E:/Croc Sentinel/croc_sentinel_systems/api/tests/test_spa_api_contract.py)