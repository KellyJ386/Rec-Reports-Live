# ADR-0003: Transactional outbox and idempotent jobs

Status: Accepted (Nov 10, 2026)

## Context
Bookings, checklists, and incidents must reliably create tasks and notifications. Firing these inline is fragile: a crash in the middle loses work, and a retry duplicates it.

## Decision
- A business change and its domain event are written in the same transaction to `outbox_events`.
- A worker (a Vercel Cron route for the pilot) claims events with `FOR UPDATE SKIP LOCKED`, runs handlers, and retries with backoff. After the attempt limit, an event moves to dead-letter.
- Generated rows carry `source_event_id`, protected by a unique constraint.

## Consequences
- At-least-once delivery with no duplicates.
- Up to about one minute of latency for generated tasks in the pilot. That's acceptable; a queue-based worker can replace the cron without changing handlers.
