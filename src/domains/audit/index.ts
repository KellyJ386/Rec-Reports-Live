// Public interface of the audit domain.
//
// Boundary rule (docs/ARCHITECTURE.md): this file is the only way code outside
// src/domains/audit may reach this domain. Export service functions from here.
// Never import another domain's internal files, only its index. ESLint
// enforces this (see eslint.config.mjs).
export * from './schemas';
export { listAuditLog } from './service';
export type { AuditEntry } from './service';
export { AUDIT_ACTIONS, AUDIT_TABLES, actionLabel, parseAuditQuery, tableLabel } from './logic';
export type { AuditFormValues, ParsedAuditQuery } from './logic';
