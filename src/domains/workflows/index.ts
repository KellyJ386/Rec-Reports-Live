// Public interface of the workflows domain (tasks, task templates, workflow rules).
//
// Boundary rule (docs/ARCHITECTURE.md): this file is the only way code outside
// src/domains/workflows may reach this domain. Export service functions from here
// as they are added. Never import another domain's internal files, only its index.
// ESLint enforces this (see eslint.config.mjs).
export * from './schemas';
export {
  addTaskComment,
  assignTask,
  cancelTask,
  completeTask,
  countMyOpenTasks,
  createTask,
  createTaskTemplate,
  createWorkflowRule,
  getTask,
  getTaskTemplate,
  getWorkflowRule,
  listBoardTasks,
  listFailedJobs,
  listMyWork,
  listTaskHistory,
  listTaskTemplates,
  listTemplateChoices,
  listWorkflowRules,
  reopenTask,
  retryFailedJob,
  setTaskTemplateArchived,
  setWorkflowRuleArchived,
  setWorkflowRuleEnabled,
  startTask,
  updateTaskTemplate,
  updateWorkflowRule,
} from './service';
export type {
  BoardQuery,
  FailedJob,
  TaskHistoryRow,
  TaskRow,
  TaskTemplate,
  TemplateChoice,
  WorkflowRule,
} from './service';
export {
  ASSIGN_TO_OPTIONS,
  BOARD_STATUS_OPTIONS,
  CLAUSE_OPS,
  CLAUSE_TYPES,
  DUE_BUCKET_LABELS,
  EMPTY_CLAUSE,
  EVENT_TYPE_OPTIONS,
  FORM_CLAUSE_ROWS,
  MAX_CLAUSES,
  OFFSET_DIRECTIONS,
  OFFSET_UNITS,
  TASK_STATUSES,
  availableTaskActions,
  conditionFromForm,
  conditionToForm,
  describeAssignee,
  describeCondition,
  describeOffset,
  dueBucket,
  errorClass,
  eventTypeLabel,
  groupByDueBucket,
  isEventType,
  jobStateLabel,
  localDateKey,
  myWorkFilter,
  offsetFromForm,
  offsetToForm,
  parseBoardFilters,
  priorityLabel,
  statusLabel,
  taskEventLabel,
} from './logic';
export type {
  BoardFilters,
  BoardStatus,
  BucketGroup,
  ClauseInput,
  DueBucket,
  OffsetInput,
  PermissionLevelName,
  TaskActions,
  TaskStatus,
  TitleScope,
  WorkflowCondition,
} from './logic';

// Background worker (outbox drain, handlers). Composed in src/lib/cron.
export { drainOutbox } from './worker/drain';
export type { DrainOptions, DrainSummary } from './worker/drain';
export { HANDLER_NAMES, taskLink } from './worker/handlers';
export { RULE_EVENT_TYPES, buildHandlerRegistry } from './worker/registry';
export { createOutboxPort, createTaskReader, createWorkflowPort } from './worker/supabase-ports';
export type {
  MatchedRule,
  TaskNotificationInput,
  TaskNotifier,
  TaskReader,
  TaskSnapshot,
  WorkflowPort,
} from './worker/types';
