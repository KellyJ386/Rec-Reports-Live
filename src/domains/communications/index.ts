// Public interface of the communications domain (notices, messages, push and
// notification preferences).
//
// Boundary rule (docs/ARCHITECTURE.md): this file is the only way code outside
// src/domains/communications may reach this domain. Export service functions from here
// as they are added. Never import another domain's internal files, only its index.
// ESLint enforces this (see eslint.config.mjs).
export * from './schemas';

// Background worker (notification fan-out and delivery). Composed in src/lib/cron.
export {
  COMMUNICATIONS_HANDLER_NAMES,
  MESSAGES_LINK,
  createMessageNotifyHandler,
  createNoticeNotifyHandler,
  noticeLink,
} from './worker/handlers';
export { deliverNotifications } from './worker/deliver';
export type { DeliverOptions, DeliverSummary } from './worker/deliver';
export { createChannels } from './worker/channels';
export { FALLBACK_BODY, absoluteLink, buildEmail, buildPushPayload } from './worker/payloads';
export {
  createDeliveryPort,
  createNoticeReader,
  createNotificationPort,
} from './worker/supabase-ports';
export { createWebPushSender } from './worker/web-push-sender';
export type {
  Channel,
  CreateNotificationsInput,
  Delivery,
  DeliveryChannel,
  DeliveryPort,
  NoticeReader,
  NoticeSnapshot,
  NotificationContent,
  NotificationPort,
  PushTarget,
  SendResult,
  Urgency,
} from './worker/types';

// Screens: notices, messages, notifications and their settings.
export {
  acknowledgeNotice,
  archiveNotice,
  countPushDevices,
  countUnreadMessages,
  countUnreadNotifications,
  createNoticeDraft,
  deletePushSubscription,
  getChannelSettings,
  getMessage,
  getMyAcknowledgment,
  getNotice,
  listAcknowledgments,
  listInbox,
  listMyNotices,
  acknowledgedIds,
  listManagedNotices,
  listNoticeAudiences,
  listNotifications,
  listSent,
  markAllNotificationsRead,
  markMessageRead,
  markNotificationsRead,
  publishNotice,
  savePushSubscription,
  sendMessage,
  setChannelEnabled,
  updateNoticeDraft,
} from './service';
export type {
  AcknowledgmentRow,
  InboxRow,
  MessageView,
  Notice,
  NoticeAudienceRow,
  NoticeSummary,
  NotificationRow,
  SentRow,
} from './service';
export {
  MAX_RECIPIENTS,
  addRecipient,
  buildAudience,
  buildAudienceOptions,
  channelSettings,
  describeAudience,
  excerpt,
  needsAcknowledgment,
  noticeStatusLabel,
  orderNoticesForReader,
  pageOf,
  parseRecipientIds,
  removeRecipient,
  safeLinkPath,
  urgencyFlag,
  urgencyLabel,
} from './logic';
export type {
  AudienceInput,
  AudienceOptions,
  AudienceRow,
  ChannelSettings,
  NoticeForOrder,
} from './logic';
