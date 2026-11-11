# ADR-0001: Modular monolith

Status: Accepted (Nov 10, 2026)

## Context
Rec Reports will eventually span many domains (operations, scheduling, registration, commerce). The team is small and AI-assisted. Microservices would add deployment, consistency, and observability cost before there is any scale to justify it.

## Decision
Build one Next.js app on one Postgres database, organized into `src/domains/*`. Each domain has its own tables and exports a service interface. Cross-domain reactions go through the outbox (ADR-0003).

## Consequences
- One deploy and one database, with transactions across a single business action.
- Boundaries are enforced by convention and lint rules (no deep imports across domains), not by the network.
- A domain can be extracted later because its tables and interface are already separate.
