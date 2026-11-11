# ADR-0005: Feature target is SubItUp plus Connect2; infrastructure before design

Status: Accepted (Nov 10, 2026, decided by Kelly). Amends ADR-0004.

## Decision
- The feature target is the functionality of SubItUp (staff scheduling, subs and swaps, time clock, timesheets, certifications) and Connect2 (forms, checklists, incident reports, headcounts, daily logs, equipment checkout) in one app. Rec Reports uses its own visual design, not a copy of either product.
- Build infrastructure and working features first on plain standard components. Visual design is a separate late phase.
- Modules that don't fit before May 1, 2027 (payroll export, certifications, equipment checkout, maintenance, lost and found, documents, dashboards) are Phase 6.

## Consequences
- `docs/PRODUCT_SPEC.md` "Deferred" still holds for registration, memberships, payments and POS.
- `docs/DATA_MODEL.md` gains tables for time clock, headcounts and the form builder as their phases start.
