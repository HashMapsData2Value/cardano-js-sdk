import { Cardano } from '@cardano-sdk/core';
import { Schema } from '@cardano-ogmios/client';
import omit from 'lodash/omit';

export const genesis = (ogmiosGenesis: Schema.CompactGenesis): Cardano.CompactGenesis => ({
  ...omit(ogmiosGenesis, 'protocolParameters'),
  activeSlotsCoefficient: (() => {
    const [nominator, denominator] = ogmiosGenesis.activeSlotsCoefficient.split('/');
    return Number(nominator) / Number(denominator);
  })(),
  maxLovelaceSupply: BigInt(ogmiosGenesis.maxLovelaceSupply),
  networkId: ogmiosGenesis.network === 'mainnet' ? Cardano.NetworkId.mainnet : Cardano.NetworkId.testnet,
  systemStart: new Date(ogmiosGenesis.systemStart)
});
