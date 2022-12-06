import { Decoded, bech32 } from 'bech32';
import { Ed25519KeyHash } from '../types/Key';
import { InvalidStringError } from '../../errors';

const MAX_BECH32_LENGTH_LIMIT = 1023;

// Source: https://github.com/Microsoft/Typescript/issues/202#issuecomment-811246768
export declare class OpaqueString<T extends string> extends String {
  /** This helps typescript distinguish different opaque string types. */
  protected readonly __opaqueString: T;
  /**
   * This object is already a string, but calling this makes method
   * makes typescript recognize it as such.
   */
  toString(): string;
}

export declare class OpaqueNumber<T extends string> extends Number {
  /** This helps typescript distinguish different opaque number types. */
  protected readonly __opaqueNumber: T;
}

const isOneOf = <T>(target: T, options: T | T[]) =>
  (Array.isArray(options) && options.includes(target)) || target === options;

export const assertIsBech32WithPrefix = (
  target: string,
  prefix: string | string[],
  expectedDecodedLength?: number | number[]
): void => {
  let decoded: Decoded;
  try {
    decoded = bech32.decode(target, MAX_BECH32_LENGTH_LIMIT);
  } catch (error) {
    throw new InvalidStringError(`expected bech32-encoded string with '${prefix}' prefix`, error);
  }
  if (!isOneOf(decoded.prefix, prefix)) {
    throw new InvalidStringError(`expected bech32 prefix '${prefix}', got '${decoded.prefix}''`);
  }
  if (expectedDecodedLength && !isOneOf(decoded.words.length, expectedDecodedLength)) {
    throw new InvalidStringError(
      `expected decoded length of '${expectedDecodedLength}', got '${decoded.words.length}'`
    );
  }
};

/**
 * @param {string} target bech32 string to decode
 * @param {string} prefix expected prefix
 * @param {string} expectedDecodedLength number of expected words, >0
 * @throws {InvalidStringError}
 */
export const typedBech32 = <T>(
  target: string,
  prefix: string | string[],
  expectedDecodedLength?: number | number[]
) => {
  assertIsBech32WithPrefix(target, prefix, expectedDecodedLength);
  return target as unknown as T;
};

const assertLength = (expectedLength: number | undefined, target: string) => {
  if (expectedLength && target.length !== expectedLength) {
    throw new InvalidStringError(`expected length '${expectedLength}', got ${target.length}`);
  }
};

/**
 * @param {string} target hex string to validate
 * @param {string} expectedLength expected string length, >0
 * @throws {InvalidStringError}
 */
export const assertIsHexString = (target: string, expectedLength?: number): void => {
  assertLength(expectedLength, target);
  // eslint-disable-next-line wrap-regex
  if (target.length > 0 && !/^[\da-f]+$/i.test(target)) {
    throw new InvalidStringError('expected hex string');
  }
};

/**
 * @param {string} value hex string to validate
 * @param {string} length expected string length, >0
 * @throws {InvalidStringError}
 */
export const typedHex = <T>(value: string, length?: number): T => {
  assertIsHexString(value, length);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return value as any as T;
};

/**
 * https://www.ietf.org/rfc/rfc4648.txt
 */
export type Base64Blob = OpaqueString<'Base64Blob'>;
export const Base64Blob = (target: string): Base64Blob => {
  // eslint-disable-next-line wrap-regex
  if (/^(?:[\d+/a-z]{4})*(?:[\d+/a-z]{2}==|[\d+/a-z]{3}=)?$/i.test(target)) {
    return target as unknown as Base64Blob;
  }
  throw new InvalidStringError('expected base64 string');
};
Base64Blob.fromBytes = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64') as unknown as Base64Blob;

export type HexBlob = OpaqueString<'HexBlob'>;
export const HexBlob = (target: string): HexBlob => typedHex(target);
HexBlob.fromBytes = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex') as unknown as HexBlob;

/**
 * Converts a hex string into a typed bech32 encoded string.
 *
 * @param prefix The prefix of the bech32 string.
 * @param hexString The hex string to be encoded.
 */
HexBlob.toTypedBech32 = <T>(prefix: string, hexString: HexBlob): T =>
  bech32.encode(prefix, bech32.toWords(Uint8Array.from(Buffer.from(hexString, 'hex')))) as unknown as T;

HexBlob.fromEd25519KeyHash = (hash: Ed25519KeyHash) => hash as unknown as HexBlob;

/**
 * Cast HexBlob it into another OpaqueString type.
 *
 * @param {HexBlob} target hex string to convert
 * @param {number} expectedLength optionally validate the length
 */
export const castHexBlob = <T>(target: HexBlob, expectedLength?: number) => {
  assertLength(expectedLength, target.toString());
  return target as unknown as T;
};

/**
 * 32 byte hash as hex string
 */
export type Hash32ByteBase16 = OpaqueString<'Hash32ByteBase16'>;

/**
 * @param {string} value 32 byte hash as hex string
 * @throws InvalidStringError
 */
export const Hash32ByteBase16 = (value: string): Hash32ByteBase16 => typedHex<Hash32ByteBase16>(value, 64);
Hash32ByteBase16.fromHexBlob = <T>(value: HexBlob) => castHexBlob<T>(value, 64);

/**
 * 28 byte hash as hex string
 */
export type Hash28ByteBase16 = OpaqueString<'Hash28ByteBase16'>;

/**
 * @param {string} value 28 byte hash as hex string
 * @throws InvalidStringError
 */
export const Hash28ByteBase16 = (value: string): Hash28ByteBase16 => typedHex<Hash28ByteBase16>(value, 56);
