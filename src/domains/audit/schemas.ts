// Input validation for the audit domain. audit_log is append-only and written only
// by database triggers, so tenants have no write schemas here. This file holds the
// read filter for the audit viewer (audit_log >= view, see docs/SECURITY.md).
import { z } from 'zod';

export const auditLogFilterSchema = z
  .strictObject({
    organization_id: z.uuid(),
    location_id: z.uuid().optional(),
    table_name: z
      .string()
      .regex(/^[a-z][a-z0-9_]{0,62}$/)
      .optional(),
    action: z.enum(['insert', 'update', 'delete']).optional(),
    since: z.iso.datetime({ offset: true }).optional(),
    until: z.iso.datetime({ offset: true }).optional(),
    limit: z.number().int().min(1).max(200).default(50),
  })
  .refine((v) => !v.since || !v.until || Date.parse(v.until) > Date.parse(v.since), {
    message: 'until must be after since',
    path: ['until'],
  });

export type AuditLogFilter = z.infer<typeof auditLogFilterSchema>;
