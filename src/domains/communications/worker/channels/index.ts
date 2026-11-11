import { createEmailChannel, type EmailChannelDeps } from './email';
import { createInAppChannel } from './in-app';
import { createPushChannel, type PushChannelDeps } from './push';
import type { DeliveryChannel } from '../types';

export { createEmailChannel, RESEND_ENDPOINT } from './email';
export type { EmailConfig, EmailChannelDeps } from './email';
export { createInAppChannel } from './in-app';
export { createPushChannel } from './push';
export type { PushChannelDeps, PushSender, PushSendOptions, VapidConfig } from './push';

/** The three channels, all with the same `send` shape. */
export function createChannels(deps: { email: EmailChannelDeps; push: PushChannelDeps }): {
  in_app: DeliveryChannel;
  email: DeliveryChannel;
  push: DeliveryChannel;
} {
  return {
    in_app: createInAppChannel(),
    email: createEmailChannel(deps.email),
    push: createPushChannel(deps.push),
  };
}
