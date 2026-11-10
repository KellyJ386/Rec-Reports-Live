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
  getPersonEffectiveLevels,
  getRole,
  getRoleGrantExcess,
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
  replaceRoleAssignment,
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
  EffectiveLevels,
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
  displayName,
  effectiveLevelKey,
  isLastActiveAssignment,
  levelExceeds,
  scopeProblem,
} from './logic';
export type { PermissionLevel } from './logic';
