/* eslint-disable @typescript-eslint/no-explicit-any */
import { AnyMessage, MethodRequest, MethodRequestMessage, MethodResponseMessage } from './types';
import { Runtime } from 'webextension-polyfill';
import { v4 as uuidv4 } from 'uuid';

export const isRequest = (message: any): message is MethodRequest =>
  typeof message === 'object' && message !== null && Array.isArray(message.args) && typeof message.method === 'string';

const looksLikeMessage = (message: any): message is AnyMessage & Record<string, unknown> =>
  typeof message === 'object' && message !== null && typeof message.messageId === 'string';

export const isRequestMessage = (message: any): message is MethodRequestMessage =>
  looksLikeMessage(message) && isRequest(message.request);

export const isResponseMessage = (message: any): message is MethodResponseMessage =>
  looksLikeMessage(message) && message.hasOwnProperty('response');

export const senderOrigin = (sender?: Runtime.MessageSender): string | null => {
  try {
    const { origin } = new URL(sender?.url || 'throw');
    return origin;
  } catch {
    return null;
  }
};

export const newMessageId = uuidv4;
