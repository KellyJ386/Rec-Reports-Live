// Public interface of the resources domain.
//
// Boundary rule (docs/ARCHITECTURE.md): this file is the only way code outside
// src/domains/resources may reach this domain. Export service functions from here.
// Never import another domain's internal files, only its index. ESLint
// enforces this (see eslint.config.mjs).
export * from './schemas';
export {
  addClosure,
  addSpaceHours,
  createSpace,
  createSpaceKind,
  getSpace,
  listClosures,
  listSpaceHours,
  listSpaceKinds,
  listSpaces,
  removeClosure,
  removeSpaceHours,
  setSpaceArchived,
  setSpaceKindArchived,
  updateSpace,
  updateSpaceKind,
} from './service';
export type { Space, SpaceClosure, SpaceHour, SpaceKind } from './service';
export {
  checkParent,
  groupHoursByDay,
  groupSpaces,
  hoursTimes,
  overlapsExisting,
  parentChoices,
} from './logic';
export type { DayHours, HoursRow, SpaceGroup, SpaceLike } from './logic';
