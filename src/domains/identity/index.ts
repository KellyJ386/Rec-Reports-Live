// Public interface of the identity domain.
//
// Boundary rule (docs/ARCHITECTURE.md): this file is the only way code outside
// src/domains/identity may reach this domain. Export service functions from here.
// Never import another domain's internal files, only its index. ESLint
// enforces this (see eslint.config.mjs).
export * from './schemas';
export {
  addPersonJobTitle,
  addRoleAssignment,
  createJobTitle,
  createPersonWithAssignment,
  createRole,
  getAccountStatus,
  getPerson,
  getPersonNames,
  getRole,
  listJobTitles,
  listModules,
  listPeople,
  listPersonJobTitles,
  listRoleAssignments,
  listRoleDefaults,
  listRoles,
  listUserPermissions,
  removePersonJobTitle,
  removeRoleAssignment,
  removeUserPermission,
  setJobTitleArchived,
  setPersonArchived,
  setRoleArchived,
  setRoleDefault,
  setUserPermission,
  updateJobTitle,
  updatePerson,
  updateRole,
} from './service';
export type {
  AccountStatus,
  JobTitle,
  ModuleRow,
  PeopleQuery,
  Person,
  PersonAssignment,
  PersonJobTitleRow,
  Role,
  UserPermissionRow,
} from './service';
export {
  assignableRoles,
  assignmentRank,
  computeEffectiveLevel,
  displayName,
  levelAtLeast,
  maxLevel,
  scopeProblem,
} from './logic';
export type { AccessAssignment, AccessOverride, PermissionLevel, RoleDefaults } from './logic';
