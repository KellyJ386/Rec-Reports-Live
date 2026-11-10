// Server-only helpers. Import from '@/lib/auth/guards' and '@/lib/auth/session'
// in server code; the pure parts (schemas, redirect, active-org, context) are
// importable anywhere.
export { requireUser, getSessionContext, getActiveOrganization } from './session';
export {
  requireOrgMember,
  requireAdmin,
  requireModulePermission,
  requireModuleAdmin,
} from './guards';
export type { SessionContext, Membership, RoleAssignment } from './context';
