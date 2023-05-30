import { Bootstrap } from '@cardano-sdk/projection';
import { Cardano } from '@cardano-sdk/core';
import { CommonProgramOptions, OgmiosProgramOptions, PosgresProgramOptions } from '../options';
import { DnsResolver, createDnsResolver } from '../utils';
import { HttpServer, HttpServerConfig } from '../../Http';
import { Logger } from 'ts-log';
import { MissingProgramOption, UnknownServiceName } from '../errors';
import { ProjectionHttpService, ProjectionName, createTypeormProjection, storeOperators } from '../../Projection';
import { ProjectorOptionDescriptions } from './types';
import { SrvRecord } from 'dns';
import { TypeormStabilityWindowBuffer, createStorePoolMetricsUpdateJob } from '@cardano-sdk/projection-typeorm';
import { URL } from 'url';
import { createLogger } from 'bunyan';
import { getConnectionConfig, getOgmiosObservableCardanoNode } from '../services';

export const PROJECTOR_API_URL_DEFAULT = new URL('http://localhost:3002');

export type ProjectorArgs = CommonProgramOptions &
  PosgresProgramOptions<''> &
  OgmiosProgramOptions & {
    dropSchema: boolean;
    dryRun: boolean;
    poolsMetricsInterval: number;
    projectionNames: ProjectionName[];
    synchronize: boolean;
    handlePolicyIds?: Cardano.PolicyId[];
  };
export interface LoadProjectorDependencies {
  dnsResolver?: (serviceName: string) => Promise<SrvRecord>;
  logger?: Logger;
}

interface ProjectionMapFactoryOptions {
  args: ProjectorArgs;
  dnsResolver: DnsResolver;
  logger: Logger;
}

const createProjectionHttpService = async (options: ProjectionMapFactoryOptions) => {
  const { args, dnsResolver, logger } = options;
  storeOperators.storePoolMetricsUpdateJob = createStorePoolMetricsUpdateJob(args.poolsMetricsInterval)();
  const cardanoNode = getOgmiosObservableCardanoNode(dnsResolver, logger, {
    ogmiosSrvServiceName: args.ogmiosSrvServiceName,
    ogmiosUrl: args.ogmiosUrl
  });
  const connectionConfig$ = getConnectionConfig(dnsResolver, 'projector', '', args);
  const buffer = new TypeormStabilityWindowBuffer({ logger });
  const { dropSchema, dryRun, projectionNames, synchronize, handlePolicyIds } = args;
  const projection$ = createTypeormProjection({
    buffer,
    connectionConfig$,
    devOptions: { dropSchema, synchronize },
    logger,
    projectionOptions: {
      handlePolicyIds
    },
    projectionSource$: Bootstrap.fromCardanoNode({
      buffer,
      cardanoNode,
      logger
    }),
    projections: projectionNames
  });
  return new ProjectionHttpService({ dryRun, projection$, projectionNames }, { logger });
};

export const loadProjector = async (args: ProjectorArgs, deps: LoadProjectorDependencies = {}): Promise<HttpServer> => {
  const supportedProjections = Object.values(ProjectionName);
  for (const projectionName of args.projectionNames) {
    if (!supportedProjections.includes(projectionName)) {
      throw new UnknownServiceName(projectionName, Object.values(ProjectionName));
    }
    if (projectionName === ProjectionName.Handle && !args.handlePolicyIds) {
      throw new MissingProgramOption(ProjectionName.Handle, ProjectorOptionDescriptions.HandlePolicyIds);
    }
  }
  const logger =
    deps?.logger ||
    createLogger({
      level: args.loggerMinSeverity,
      name: 'projector'
    });
  const dnsResolver =
    deps?.dnsResolver ||
    createDnsResolver(
      {
        factor: args.serviceDiscoveryBackoffFactor,
        maxRetryTime: args.serviceDiscoveryTimeout
      },
      logger
    );
  const service = await createProjectionHttpService({ args, dnsResolver, logger });
  const config: HttpServerConfig = {
    listen: {
      host: args.apiUrl.hostname,
      port: args.apiUrl ? Number.parseInt(args.apiUrl.port) : undefined
    },
    meta: { ...args.buildInfo, startupTime: Date.now() }
  };
  if (args.enableMetrics) {
    config.metrics = { enabled: args.enableMetrics };
  }
  return new HttpServer(config, { logger, services: [service] });
};
