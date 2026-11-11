// Public interface of the organizations domain.
//
// Boundary rule (docs/ARCHITECTURE.md): this file is the only way code outside
// src/domains/organizations may reach this domain. Export service functions from here.
// Never import another domain's internal files, only its index. ESLint
// enforces this (see eslint.config.mjs).
export * from './schemas';
export {
  createLocation,
  getLocation,
  getOrganization,
  getOrganizationSettings,
  getStaffingSwitches,
  listAllLocations,
  listLocations,
  setLocationArchived,
  updateLocation,
  updateOrganization,
  updateOrganizationSettings,
  updateStaffingSwitches,
} from './service';
export type {
  Location,
  OrganizationSettings,
  OrganizationSummary,
  StaffingSwitches,
} from './service';
