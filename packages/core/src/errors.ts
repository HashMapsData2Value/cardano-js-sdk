import { ComposableError } from '@cardano-sdk/util';
import { CustomError } from 'ts-custom-error';

export enum ProviderFailure {
  NotFound = 'NOT_FOUND',
  Unknown = 'UNKNOWN',
  InvalidResponse = 'INVALID_RESPONSE',
  NotImplemented = 'NOT_IMPLEMENTED',
  Unhealthy = 'UNHEALTHY',
  ConnectionFailure = 'CONNECTION_FAILURE',
  BadRequest = 'BAD_REQUEST'
}

export const providerFailureToStatusCodeMap: { [key in ProviderFailure]: number } = {
  [ProviderFailure.BadRequest]: 400,
  [ProviderFailure.NotFound]: 404,
  [ProviderFailure.Unhealthy]: 500,
  [ProviderFailure.Unknown]: 500,
  [ProviderFailure.InvalidResponse]: 500,
  [ProviderFailure.NotImplemented]: 500,
  [ProviderFailure.ConnectionFailure]: 500
};

const formatMessage = (reason: string, detail?: string) => reason + (detail ? ` (${detail})` : '');

export class ProviderError<InnerError = unknown> extends ComposableError<InnerError> {
  constructor(public reason: ProviderFailure, innerError?: InnerError, public detail?: string) {
    super(formatMessage(reason, detail), innerError);
  }
}

export enum SerializationFailure {
  InvalidType = 'INVALID_TYPE',
  Overflow = 'OVERFLOW',
  InvalidAddress = 'INVALID_ADDRESS',
  MaxLengthLimit = 'MAX_LENGTH_LIMIT',
  InvalidScript = 'INVALID_SCRIPT',
  InvalidNativeScriptKind = 'INVALID_NATIVE_SCRIPT_KIND',
  InvalidScriptType = 'INVALID_SCRIPT_TYPE',
  InvalidDatum = 'INVALID_DATUM'
}

export class SerializationError<InnerError = unknown> extends ComposableError<InnerError> {
  constructor(public reason: SerializationFailure, public detail?: string, innerError?: InnerError) {
    super(formatMessage(reason, detail), innerError);
  }
}

export class InvalidProtocolParametersError extends CustomError {
  public constructor(reason: string) {
    super(reason);
  }
}

export class NotImplementedError extends CustomError {
  public constructor(missingFeature: string) {
    super(`Not implemented: ${missingFeature}`);
  }
}
