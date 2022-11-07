/* eslint-disable max-len */
/* eslint-disable promise/no-nesting */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { CommonOptionDescriptions, CommonProgramOptions } from '../Options';
import { DnsResolver } from '../utils';
import { Logger } from 'ts-log';
import { MissingCardanoNodeOption } from '../errors';
import { OgmiosCardanoNode, OgmiosTxSubmitProvider, urlToConnectionConfig } from '@cardano-sdk/ogmios';
import { SubmitTxArgs } from '@cardano-sdk/core';
import { isConnectionError } from '@cardano-sdk/util';

const isCardanoNodeOperation = (prop: string | symbol): prop is 'eraSummaries' | 'systemStart' | 'stakeDistribution' =>
  ['eraSummaries', 'systemStart', 'stakeDistribution'].includes(prop as string);

const recreateOgmiosCardanoNode = async (
  serviceName: string,
  ogmiosCardanoNode: OgmiosCardanoNode,
  dnsResolver: DnsResolver,
  logger: Logger
) => {
  const record = await dnsResolver(serviceName!);
  logger.info(`DNS resolution for Ogmios service, resolved with record: ${JSON.stringify(record)}`);
  await ogmiosCardanoNode
    .shutdown?.()
    .catch((error_) => logger.warn(`Ogmios cardano node failed to shutdown after connection error: ${error_}`));
  return new OgmiosCardanoNode({ host: record.name, port: record.port }, logger);
};

const recreateOgmiosTxSubmitProvider = async (
  serviceName: string,
  ogmiosTxSubmitProvider: OgmiosTxSubmitProvider,
  dnsResolver: DnsResolver,
  logger: Logger
) => {
  const record = await dnsResolver(serviceName!);
  logger.info(`DNS resolution for OgmiosTxSubmitProvider, resolved with record: ${JSON.stringify(record)}`);
  await ogmiosTxSubmitProvider
    .shutdown()
    .catch((error_) => logger.warn(`OgmiosTxSubmitProvider failed to shutdown after connection error: ${error_}`));
  return new OgmiosTxSubmitProvider({ host: record.name, port: record.port }, logger);
};
/**
 * Creates an extended TxSubmitProvider instance :
 * - use passed srv service name in order to resolve the port
 * - make dealing with fail-overs (re-resolving the port) opaque
 * - use exponential backoff retry internally with default timeout and factor
 * - intercept 'initialize' operation and handle connection errors on initialization
 * - intercept 'submitTx' operation and handle connection errors runtime
 * - all other operations are bind to pool object without modifications
 *
 * @returns TxSubmitProvider instance
 */
export const ogmiosTxSubmitProviderWithDiscovery = async (
  dnsResolver: DnsResolver,
  logger: Logger,
  serviceName: string
): Promise<OgmiosTxSubmitProvider> => {
  const { name, port } = await dnsResolver(serviceName!);
  let ogmiosProvider = new OgmiosTxSubmitProvider({ host: name, port }, logger);

  return new Proxy<OgmiosTxSubmitProvider>({} as OgmiosTxSubmitProvider, {
    get(_, prop) {
      if (prop === 'then') return;
      if (prop === 'initialize') {
        return () =>
          ogmiosProvider.initialize().catch(async (error) => {
            if (isConnectionError(error)) {
              ogmiosProvider = await recreateOgmiosTxSubmitProvider(serviceName, ogmiosProvider, dnsResolver, logger);
              return await ogmiosProvider.initialize();
            }
            throw error;
          });
      }
      if (prop === 'submitTx') {
        return (submitTxArgs: SubmitTxArgs) =>
          ogmiosProvider.submitTx(submitTxArgs).catch(async (error) => {
            if (isConnectionError(error)) {
              ogmiosProvider = await recreateOgmiosTxSubmitProvider(serviceName, ogmiosProvider, dnsResolver, logger);
              await ogmiosProvider.initialize();
              await ogmiosProvider.start();
              return await ogmiosProvider.submitTx(submitTxArgs);
            }
            throw error;
          });
      }
      // Bind if it is a function, no intercept operations
      if (typeof ogmiosProvider[prop as keyof OgmiosTxSubmitProvider] === 'function') {
        const method = ogmiosProvider[prop as keyof OgmiosTxSubmitProvider] as any;
        return method.bind(ogmiosProvider);
      }

      return ogmiosProvider[prop as keyof OgmiosTxSubmitProvider];
    }
  });
};

export const getOgmiosTxSubmitProvider = async (
  dnsResolver: DnsResolver,
  logger: Logger,
  options?: CommonProgramOptions
): Promise<OgmiosTxSubmitProvider> => {
  if (options?.ogmiosSrvServiceName)
    return ogmiosTxSubmitProviderWithDiscovery(dnsResolver, logger, options.ogmiosSrvServiceName);
  if (options?.ogmiosUrl) return new OgmiosTxSubmitProvider(urlToConnectionConfig(options?.ogmiosUrl), logger);
  throw new MissingCardanoNodeOption([
    CommonOptionDescriptions.OgmiosUrl,
    CommonOptionDescriptions.OgmiosSrvServiceName
  ]);
};

/**
 * Creates an extended OgmiosCardanoNode instance :
 * - use passed srv service name in order to resolve the port
 * - make dealing with fail-overs (re-resolving the port) opaque
 * - use exponential backoff retry internally with default timeout and factor
 * - intercept 'initialize' operation and handle connection errors on initialization
 * - intercept 'eraSummaries', 'systemStart' and 'stakeDistribution' operations and handle connection errors runtime
 * - all other operations are bind to pool object without modifications
 *
 * @returns OgmiosCardanoNode instance
 */
export const ogmiosCardanoNodeWithDiscovery = async (
  dnsResolver: DnsResolver,
  logger: Logger,
  serviceName: string
): Promise<OgmiosCardanoNode> => {
  const { name, port } = await dnsResolver(serviceName!);
  let ogmiosCardanoNode = new OgmiosCardanoNode({ host: name, port }, logger);

  return new Proxy<OgmiosCardanoNode>({} as OgmiosCardanoNode, {
    get(_, prop) {
      if (prop === 'then') return;
      if (prop === 'initialize') {
        return () =>
          ogmiosCardanoNode.initialize().catch(async (error) => {
            if (isConnectionError(error)) {
              ogmiosCardanoNode = await recreateOgmiosCardanoNode(serviceName, ogmiosCardanoNode, dnsResolver, logger);
              return await ogmiosCardanoNode.initialize();
            }
            throw error;
          });
      }
      if (isCardanoNodeOperation(prop)) {
        return () =>
          ogmiosCardanoNode[prop]().catch(async (error) => {
            if (isConnectionError(error)) {
              ogmiosCardanoNode = await recreateOgmiosCardanoNode(serviceName, ogmiosCardanoNode, dnsResolver, logger);
              await ogmiosCardanoNode.initialize();
              await ogmiosCardanoNode.start();
              return await ogmiosCardanoNode[prop]();
            }
            throw error;
          });
      }
      // Bind if it is a function, no intercept operations
      if (typeof ogmiosCardanoNode[prop as keyof OgmiosCardanoNode] === 'function') {
        const method = ogmiosCardanoNode[prop as keyof OgmiosCardanoNode] as any;
        return method.bind(ogmiosCardanoNode);
      }

      return ogmiosCardanoNode[prop as keyof OgmiosCardanoNode];
    }
  });
};

export const getOgmiosCardanoNode = async (
  dnsResolver: DnsResolver,
  logger: Logger,
  options?: CommonProgramOptions
): Promise<OgmiosCardanoNode> => {
  if (options?.ogmiosSrvServiceName)
    return ogmiosCardanoNodeWithDiscovery(dnsResolver, logger, options.ogmiosSrvServiceName);
  if (options?.ogmiosUrl) return new OgmiosCardanoNode(urlToConnectionConfig(options.ogmiosUrl), logger);
  throw new MissingCardanoNodeOption([
    CommonOptionDescriptions.OgmiosUrl,
    CommonOptionDescriptions.OgmiosSrvServiceName
  ]);
};
