/* eslint-disable @typescript-eslint/no-explicit-any */
import { Events, Runtime } from 'webextension-polyfill';
import { Logger } from 'ts-log';
import { Observable } from 'rxjs';
import { util } from '@cardano-sdk/core';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MethodRequest<Method extends string = string, Args = unknown[]> = { method: Method; args: Args };

export interface AnyMessage extends Object {
  messageId: string;
}

export interface MethodRequestMessage extends AnyMessage {
  request: MethodRequest;
}

export interface MethodResponseMessage<T = unknown> extends AnyMessage {
  response: T;
}

export type SendMethodRequestMessage = <Response = unknown>(msg: MethodRequest) => Promise<Response>;

/**
 * Corresponds to underlying port name
 */
export type ChannelName = string;

export type MinimalEvent<Callback extends (...args: any[]) => any> = Pick<
  Events.Event<Callback>,
  'addListener' | 'removeListener'
>;

export interface MessengerPort {
  name: string;
  sender?: Runtime.MessageSender;
  onDisconnect: MinimalEvent<(port: MessengerPort) => void>;
  onMessage: MinimalEvent<(data: unknown, port: MessengerPort) => void>;
  disconnect(): void;
  postMessage(message: any): void;
}

export interface MinimalRuntime {
  connect(connectInfo: Runtime.ConnectConnectInfoType): MessengerPort;
  onConnect: MinimalEvent<(port: MessengerPort) => void>;
}

export interface MessengerDependencies {
  runtime: MinimalRuntime;
  logger: Logger;
}

export type TransformRequest = (request: MethodRequest, sender?: Runtime.MessageSender) => MethodRequest;
export type ValidateRequest = (request: MethodRequest, sender?: Runtime.MessageSender) => Promise<void>;

export interface ReconnectConfig {
  initialDelay: number;
  maxDelay: number;
}

export interface MessengerOptions {
  /**
   * Only used in non-background process for now
   */
  reconnectConfig?: ReconnectConfig;
}

export interface ExposeApiProps<API extends object> extends MessengerOptions {
  baseChannel: ChannelName;
  api: API;
  methodRequestOptions?: {
    transform?: TransformRequest;
    validate?: ValidateRequest;
  };
}

export interface BindRequestHandlerOptions<Response> {
  handler: (request: MethodRequest, sender?: Runtime.MessageSender) => Promise<Response>;
}

export interface PortMessage<Data = unknown> {
  data: Data;
  port: Pick<MessengerPort, 'sender' | 'postMessage'>;
}

export enum RemoteApiProperty {
  MethodReturningPromise
  // TODO
  // eslint-disable-next-line @typescript-eslint/no-shadow
  // Observable
}

export type RemoteApiProperties<T> = {
  [key in keyof T]: RemoteApiProperty | RemoteApiProperties<T[key]>;
};

export interface ConsumeRemoteApiOptions<T> extends MessengerOptions {
  baseChannel: ChannelName;
  properties: RemoteApiProperties<T>;
  getErrorPrototype?: util.GetErrorPrototype;
}

export interface Messenger {
  channel: ChannelName;
  postMessage(message: unknown): Observable<void>;
  message$: Observable<PortMessage>;
}

export interface MessengerApiDependencies {
  messenger: Messenger;
  logger: Logger;
}
