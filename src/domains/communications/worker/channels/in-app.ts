import type { DeliveryChannel } from '../types';

/**
 * In-app: the notification row is the delivery, and create_notification records it as sent when
 * it makes the row. Nothing to send. (claim_notification_deliveries never returns in_app rows;
 * this exists so every channel has the same shape.)
 */
export function createInAppChannel(): DeliveryChannel {
  return {
    channel: 'in_app',
    async send() {
      return { outcome: 'sent' };
    },
  };
}
