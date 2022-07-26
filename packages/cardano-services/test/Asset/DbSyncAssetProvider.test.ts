import { Asset, Cardano, ProviderError } from '@cardano-sdk/core';
import {
  CardanoTokenRegistry,
  DbSyncAssetProvider,
  DbSyncNftMetadataService,
  NftMetadataService,
  TokenMetadataService
} from '../../src/Asset';
import { Pool } from 'pg';
import { createDbSyncMetadataService } from '../../src/Metadata';
import { dummyLogger as logger } from 'ts-log';
import { mockTokenRegistry } from './CardanoTokenRegistry.test';

export const notValidAssetId = Cardano.AssetId('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
export const validAssetId = Cardano.AssetId(
  '50fdcdbfa3154db86a87e4b5697ae30d272e0bbcfa8122efd3e301cb6d616361726f6e2d63616b65'
);

describe('DbSyncAssetProvider', () => {
  let closeMock: () => Promise<void> = jest.fn();
  let db: Pool;
  let ntfMetadataService: NftMetadataService;
  let provider: DbSyncAssetProvider;
  let tokenMetadataServerUrl = '';
  let tokenMetadataService: TokenMetadataService;

  beforeAll(async () => {
    ({ closeMock, tokenMetadataServerUrl } = await mockTokenRegistry(() => ({})));
    db = new Pool({ connectionString: process.env.DB_CONNECTION_STRING });
    ntfMetadataService = new DbSyncNftMetadataService({
      db,
      logger,
      metadataService: createDbSyncMetadataService(db, logger)
    });
    tokenMetadataService = new CardanoTokenRegistry({ logger }, { tokenMetadataServerUrl });
    provider = new DbSyncAssetProvider({ db, logger, ntfMetadataService, tokenMetadataService });
  });

  afterAll(async () => {
    tokenMetadataService.shutdown();
    await db.end();
    await closeMock();
  });

  it('rejects for not found assetId', async () => {
    await expect(provider.getAsset(notValidAssetId)).rejects.toThrow(ProviderError);
  });

  it('returns an AssetInfo without extra data', async () => {
    expect(await provider.getAsset(validAssetId)).toEqual({
      assetId: '50fdcdbfa3154db86a87e4b5697ae30d272e0bbcfa8122efd3e301cb6d616361726f6e2d63616b65',
      fingerprint: 'asset1f0azzptnr8dghzjh7egqvdjmt33e3lz5uy59th',
      mintOrBurnCount: 1,
      name: '6d616361726f6e2d63616b65',
      policyId: '50fdcdbfa3154db86a87e4b5697ae30d272e0bbcfa8122efd3e301cb',
      quantity: 1n
    });
  });

  it('returns an AssetInfo with extra data', async () => {
    const asset = await provider.getAsset(validAssetId, { history: true, nftMetadata: true, tokenMetadata: true });

    expect(asset.history).toEqual([
      { quantity: BigInt(1), transactionId: 'f66791a0354c43d8c5a93671eb96d94633e3419f3ccbb0a00c00a152d3b6ca06' }
    ]);
    expect(asset.nftMetadata).toStrictEqual({
      description: ['This is my first NFT of the macaron cake'],
      files: undefined,
      image: [Asset.Uri('ipfs://QmcDAmZubQig7tGUgEwbWcgdvz4Aoa2EiRZyFoX3fXTVmr')],
      mediaType: undefined,
      name: 'macaron cake token',
      otherProperties: new Map([['id', 1n]]),
      version: '1.0'
    });
    expect(asset.tokenMetadata).toStrictEqual({
      desc: 'This is my first NFT of the macaron cake',
      name: 'macaron cake token'
    });
  });
});