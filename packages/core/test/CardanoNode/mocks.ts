import { Cardano, EraSummary, StakeDistribution } from '@cardano-sdk/core';

const mockEraSummaries: EraSummary[] = [
  { parameters: { epochLength: 21_600, slotLength: 20_000 }, start: { slot: 0, time: new Date(1_563_999_616_000) } },
  {
    parameters: { epochLength: 432_000, slotLength: 1000 },
    start: { slot: 1_598_400, time: new Date(1_595_964_016_000) }
  }
];

export const mockStakeDistribution: StakeDistribution = new Map([
  [
    Cardano.PoolId('pool1la4ghj4w4f8p4yk4qmx0qvqmzv6592ee9rs0vgla5w6lc2nc8w5'),
    {
      stake: { pool: 10_098_109_508n, supply: 40_453_712_883_332_027n },
      vrf: Cardano.VrfVkHex('4e4a2e82dc455449bf5f1f6d249470963cf97389b5dc4d2118fe21625f50f518')
    }
  ],
  [
    Cardano.PoolId('pool1lad5j5kawu60qljfqh02vnazxrahtaaj6cpaz4xeluw5xf023cg'),
    {
      stake: {
        pool: 14_255_969_766n,
        supply: 40_453_712_883_332_027n
      },
      vrf: Cardano.VrfVkHex('474a6d2a44b51add62d8f2fd8fe80abc722bf84478479b617ad05b39aaa84971')
    }
  ],
  [
    Cardano.PoolId('pool1llugtz5r4t6m7xz6es4qu7cszllm5y3uvx3ast5a9jzlv7h3xdu'),
    {
      stake: {
        pool: 98_763_124_501_826n,
        supply: 40_453_712_883_332_027n
      },
      vrf: Cardano.VrfVkHex('dc1c0fd7d2fd95b6e9bf0e50ab5cb722edbd7d6e85b7d53323884d429ec6a83c')
    }
  ],
  [
    Cardano.PoolId('pool1lu6ll4rcxm92059ggy6uym2p804s5hcwqyyn5vyqhy35kuxtn2f'),
    {
      stake: {
        pool: 1_494_933_206n,
        supply: 40_453_712_883_332_027n
      },
      vrf: Cardano.VrfVkHex('4a13d5e99a1868788057bf401fdb4379b7846290dd948918839981088059a564')
    }
  ]
]);

export const mockCardanoNode = () => ({
  eraSummaries: jest.fn(() => Promise.resolve(mockEraSummaries)),
  initialize: jest.fn(() => Promise.resolve()),
  shutdown: jest.fn(() => Promise.resolve()),
  stakeDistribution: jest.fn(() => Promise.resolve(mockStakeDistribution)),
  systemStart: jest.fn(() => Promise.resolve(new Date(1_563_999_616_000)))
});
