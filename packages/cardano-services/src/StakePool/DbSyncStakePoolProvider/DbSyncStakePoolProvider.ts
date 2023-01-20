import {
  Cardano,
  Paginated,
  ProviderError,
  ProviderFailure,
  QueryStakePoolsArgs,
  StakePoolProvider,
  StakePoolStats
} from '@cardano-sdk/core';
import { CommonPoolInfo, OrderedResult, PoolAPY, PoolData, PoolMetrics, PoolSortType, PoolUpdate } from './types';
import { DbSyncProvider, DbSyncProviderDependencies } from '../../util/DbSyncProvider';
import { Disposer, EpochMonitor } from '../../util/polling/types';
import { IDS_NAMESPACE, StakePoolsSubQuery, emptyPoolsExtraInfo, getStakePoolSortType, queryCacheKey } from './util';
import { InMemoryCache, UNLIMITED_CACHE_TTL } from '../../InMemoryCache';
import { RunnableModule, isNotNil } from '@cardano-sdk/util';
import { StakePoolBuilder } from './StakePoolBuilder';
import { StakePoolExtMetadataService } from '../types';
import { toStakePoolResults } from './mappers';

/**
 * Properties that are need to create DbSyncStakePoolProvider
 */
export interface StakePoolProviderProps {
  /**
   * Pagination page size limit used for provider methods constraint.
   */
  paginationPageSizeLimit: number;
}

/**
 * Dependencies that are need to create DbSyncStakePoolProvider
 */
export interface StakePoolProviderDependencies extends DbSyncProviderDependencies {
  /**
   *The in memory cache engine.
   */
  cache: InMemoryCache;
  /**
   * Monitor the epoch rollover through db polling.
   */
  epochMonitor: EpochMonitor;
  /**
   * The Stake Pool extended metadata service.
   */
  metadataService: StakePoolExtMetadataService;
}

export class DbSyncStakePoolProvider extends DbSyncProvider(RunnableModule) implements StakePoolProvider {
  #builder: StakePoolBuilder;
  #cache: InMemoryCache;
  #epochMonitor: EpochMonitor;
  #epochRolloverDisposer: Disposer;
  #paginationPageSizeLimit: number;
  #metadataService: StakePoolExtMetadataService;

  constructor(
    { paginationPageSizeLimit }: StakePoolProviderProps,
    { db, cardanoNode, metadataService, cache, logger, epochMonitor }: StakePoolProviderDependencies
  ) {
    super({ cardanoNode, db, logger }, 'DbSyncStakePoolProvider', logger);
    this.#cache = cache;
    this.#epochMonitor = epochMonitor;
    this.#builder = new StakePoolBuilder(db, logger);
    this.#paginationPageSizeLimit = paginationPageSizeLimit;
    this.#metadataService = metadataService;
  }

  private getQueryBySortType(
    sortType: PoolSortType,
    queryArgs: { hashesIds: number[]; updatesIds: number[]; totalAdaAmount: string }
  ) {
    const { hashesIds, updatesIds, totalAdaAmount } = queryArgs;
    // Identify which query to use to order and paginate the result
    // Should be the only one to get the sort options, rest should be ordered by their own defaults
    switch (sortType) {
      // Add more cases as more sort types are supported
      case 'metrics':
        return (options?: QueryStakePoolsArgs) => this.#builder.queryPoolMetrics(hashesIds, totalAdaAmount, options);
      case 'apy':
        return (options?: QueryStakePoolsArgs) => this.#builder.queryPoolAPY(hashesIds, options);
      case 'data':
      default:
        return (options?: QueryStakePoolsArgs) => this.#builder.queryPoolData(updatesIds, options);
    }
  }

  private async attachExtendedMetadata(poolData: PoolData[]): Promise<void> {
    for (const pool of poolData) {
      if (pool.metadata?.extDataUrl || pool.metadata?.extended) {
        try {
          pool.metadata.ext = await this.#metadataService.getStakePoolExtendedMetadata(pool.metadata);
        } catch (error) {
          if (error instanceof ProviderError && error.reason === ProviderFailure.ConnectionFailure) {
            pool.metadata.ext = undefined;
          } else if (error instanceof ProviderError && error.reason === ProviderFailure.NotFound) {
            pool.metadata.ext = null;
          } else {
            throw error;
          }
        }
      }
    }
  }

  private async getPoolsDataOrdered(poolUpdates: PoolUpdate[], totalAdaAmount: string, options?: QueryStakePoolsArgs) {
    const hashesIds = poolUpdates.map(({ id }) => id);
    const updatesIds = poolUpdates.map(({ updateId }) => updateId);
    this.logger.debug(`${hashesIds.length} pools found`);
    const sortType = options?.sort?.field ? getStakePoolSortType(options.sort.field) : 'data';
    const orderedResult = await this.getQueryBySortType(sortType, { hashesIds, totalAdaAmount, updatesIds })(options);
    const orderedResultHashIds = (orderedResult as CommonPoolInfo[]).map(({ hashId }) => hashId);
    const orderedResultUpdateIds = orderedResultHashIds.map(
      (id) => poolUpdates[poolUpdates.findIndex((item) => item.id === id)].updateId
    );
    let poolDatas: PoolData[] = [];
    if (sortType !== 'data') {
      this.logger.debug('About to query stake pools data');
      poolDatas = await this.#builder.queryPoolData(orderedResultUpdateIds);
    } else {
      poolDatas = orderedResult as PoolData[];
    }

    await this.attachExtendedMetadata(poolDatas);
    return { hashesIds, orderedResult, orderedResultHashIds, orderedResultUpdateIds, poolDatas, sortType };
  }

  private cacheStakePools(itemsToCache: { [hashId: number]: Cardano.StakePool }) {
    for (const [hashId, pool] of Object.entries(itemsToCache))
      this.#cache.set(`${IDS_NAMESPACE}/${hashId}`, pool, UNLIMITED_CACHE_TTL);
  }

  private async queryExtraPoolsData(
    idsToFetch: PoolUpdate[],
    sortType: PoolSortType,
    totalAdaAmount: string,
    orderedResult: OrderedResult
  ) {
    if (idsToFetch.length === 0) return emptyPoolsExtraInfo;
    this.logger.debug('About to query stake pool extra information');
    const orderedResultHashIds = idsToFetch.map(({ id }) => id);
    const orderedResultUpdateIds = idsToFetch.map(({ updateId }) => updateId);
    const [poolRelays, poolOwners, poolRegistrations, poolRetirements, poolMetrics] = await Promise.all([
      // TODO: it would be easier and make the code cleaner if all queries had the same id as argument
      //       (either hash or update id)
      this.#builder.queryPoolRelays(orderedResultUpdateIds),
      this.#builder.queryPoolOwners(orderedResultUpdateIds),
      this.#builder.queryRegistrations(orderedResultHashIds),
      this.#builder.queryRetirements(orderedResultHashIds),
      sortType === 'metrics'
        ? (orderedResult as PoolMetrics[])
        : this.#builder.queryPoolMetrics(orderedResultHashIds, totalAdaAmount)
    ]);
    return { poolMetrics, poolOwners, poolRegistrations, poolRelays, poolRetirements };
  }
  public async queryStakePools(options: QueryStakePoolsArgs): Promise<Paginated<Cardano.StakePool>> {
    if (options.pagination.limit > this.#paginationPageSizeLimit) {
      throw new ProviderError(
        ProviderFailure.BadRequest,
        undefined,
        `Page size of ${options.pagination.limit} can not be greater than ${this.#paginationPageSizeLimit}`
      );
    }
    if (options.filters?.identifier && options.filters.identifier.values.length > this.#paginationPageSizeLimit) {
      throw new ProviderError(
        ProviderFailure.BadRequest,
        undefined,
        `Filter identifiers of ${options.filters.identifier.values.length} can not be greater than ${
          this.#paginationPageSizeLimit
        }`
      );
    }
    const { params, query } =
      options.filters?._condition === 'or'
        ? this.#builder.buildOrQuery(options.filters)
        : this.#builder.buildAndQuery(options.filters);
    // Get pool updates/hashes cached
    const poolUpdates = await this.#cache.get(queryCacheKey(StakePoolsSubQuery.POOL_HASHES, options), () =>
      this.#builder.queryPoolHashes(query, params)
    );
    // Get total amount of ada cached
    const totalAdaAmount = await this.#cache.get(queryCacheKey(StakePoolsSubQuery.TOTAL_ADA_AMOUNT), () =>
      this.#builder.getTotalAmountOfAda()
    );
    // Get total stake pools count cached
    const totalCount = await this.#cache.get(queryCacheKey(StakePoolsSubQuery.TOTAL_POOLS_COUNT, options), () =>
      this.#builder.queryTotalCount(query, params)
    );
    // Get last epoch data
    const lastEpoch = await this.#builder.getLastEpochWithData();
    const { optimalPoolCount, no: lastEpochNo } = lastEpoch;
    // Get stake pools data cached
    const { orderedResultHashIds, orderedResultUpdateIds, orderedResult, poolDatas, hashesIds, sortType } =
      await this.#cache.get(queryCacheKey(StakePoolsSubQuery.POOLS_DATA_ORDERED, options), () =>
        this.getPoolsDataOrdered(poolUpdates, totalAdaAmount, options)
      );
    // Get stake pools APYs cached
    const poolAPYs =
      sortType === 'apy'
        ? (orderedResult as PoolAPY[])
        : await this.#cache.get(queryCacheKey(StakePoolsSubQuery.APY, hashesIds, options), () =>
            this.#builder.queryPoolAPY(hashesIds, { rewardsHistoryLimit: options?.rewardsHistoryLimit })
          );

    // Get stake pools rewards cached
    const poolRewards = await this.#cache.get(
      queryCacheKey(StakePoolsSubQuery.REWARDS, orderedResultHashIds, options),
      () => this.#builder.queryPoolRewards(orderedResultHashIds, options?.rewardsHistoryLimit),
      UNLIMITED_CACHE_TTL
    );
    // Create lookup table with pool ids: (hashId:updateId)
    const hashIdsMap = Object.fromEntries(
      orderedResultHashIds.map((hashId, idx) => [hashId, orderedResultUpdateIds[idx]])
    );
    // Create a lookup table with cached pools: (hashId:Cardano.StakePool)
    const fromCache = Object.fromEntries(
      orderedResultHashIds.map((hashId) => [
        hashId,
        this.#cache.getVal<Cardano.StakePool>(`${IDS_NAMESPACE}/${hashId}`)
      ])
    );
    // Compute ids to fetch from db
    const idsToFetch = Object.entries(fromCache)
      .filter(([_, pool]) => pool === undefined)
      .map(([hashId, _]) => ({ id: Number(hashId), updateId: hashIdsMap[hashId] }));
    // Get stake pools extra information
    const { poolRelays, poolOwners, poolRegistrations, poolRetirements, poolMetrics } = await this.queryExtraPoolsData(
      idsToFetch,
      sortType,
      totalAdaAmount,
      orderedResult
    );
    const { results, poolsToCache } = toStakePoolResults(orderedResultHashIds, fromCache, {
      lastEpochNo: Cardano.EpochNo(lastEpochNo),
      nodeMetricsDependencies: {
        optimalPoolCount,
        totalAdaAmount: BigInt(totalAdaAmount)
      },
      poolAPYs,
      poolDatas,
      poolMetrics,
      poolOwners,
      poolRegistrations,
      poolRelays,
      poolRetirements,
      poolRewards: poolRewards.filter(isNotNil),
      totalCount
    });
    // Cache stake pools core objects
    this.cacheStakePools(poolsToCache);
    return results;
  }

  public async stakePoolStats(): Promise<StakePoolStats> {
    this.logger.debug('About to query pool stats');
    return await this.#cache.get(queryCacheKey(StakePoolsSubQuery.STATS), () => this.#builder.queryPoolStats());
  }

  async initializeImpl() {
    return Promise.resolve();
  }

  async startImpl() {
    this.#epochRolloverDisposer = this.#epochMonitor.onEpochRollover(() => this.#cache.clear());
  }

  async shutdownImpl() {
    this.#cache.shutdown();
    this.#epochRolloverDisposer();
  }
}
