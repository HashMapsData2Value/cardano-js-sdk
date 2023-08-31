import { Asset, Cardano, Handle, Serialization } from '@cardano-sdk/core';
import { HexBlob } from '@cardano-sdk/util';
import { mockProviders } from '@cardano-sdk/util-dev';

export const handleAssetName = (handle: Handle) => Cardano.AssetName(Buffer.from(handle).toString('hex'));

export const handleAssetId = (assetName: string, policyId: Cardano.PolicyId): Cardano.AssetId =>
  Cardano.AssetId.fromParts(policyId, handleAssetName(assetName));

export const handlePolicyId = mockProviders.handlePolicyId;
export const assetIdFromHandle = (handle: string) => handleAssetId(handle, handlePolicyId);

export const bobAddress = Cardano.PaymentAddress('addr_test1wzlv9cslk9tcj0wpm9p5t6kajyt37ap5sc9rzkaxa9p67ys2ygypv');
export const maryAddress = Cardano.PaymentAddress(
  'addr_test1qretqkqqvc4dax3482tpjdazrfl8exey274m3mzch3dv8lu476aeq3kd8q8splpsswcfmv4y370e8r76rc8lnnhte49qqyjmtc'
);
export const bobHandleOne = 'bob.handle.one';
export const bobHandleTwo = 'bob.handle.two';
export const maryHandleOne = 'mary.handle.one';
export const handleOutputs = {
  maryHandleToBob: {
    address: bobAddress,
    value: {
      assets: new Map([[assetIdFromHandle(maryHandleOne), 1n]]),
      coins: 25_485_292n
    }
  },
  noHandlesCoinsOnly: {
    address: 'addr_test1vptwv4jvaqt635jvthpa29lww3vkzypm8l6vk4lv4tqfhhgajdgwf',
    value: {
      coins: 74_341_815n
    }
  },
  noHandlesEmptyAssets: {
    address: 'addr_test1vptwv4jvaqt635jvthpa29lww3vkzypm8l6vk4lv4tqfhhgajdgwf',
    value: {
      assets: new Map(),
      coins: 74_341_815n
    }
  },
  noHandlesOtherAsset: {
    address: 'addr_test1vptwv4jvaqt635jvthpa29lww3vkzypm8l6vk4lv4tqfhhgajdgwf',
    value: {
      assets: new Map([
        [Cardano.AssetId('8f78a4388b1a3e1a1435257e9356fa0c2cc0d3a5999d63b5886c96435365636f6e6454657374746f6b656e'), 3n]
      ]),
      coins: 74_341_815n
    }
  },
  oneHandleMary: {
    address: maryAddress,
    value: {
      assets: new Map([[assetIdFromHandle(maryHandleOne), 1n]]),
      coins: 25_485_292n
    }
  },
  twoHandlesBob: {
    address: bobAddress,
    datumHash: '99c170cc1247e7b7971e194c7e400e219360d3991cb588e9833f77ee9edbbd06' as Cardano.DatumHash,
    value: {
      assets: new Map([
        [assetIdFromHandle(bobHandleOne), 1n],
        [assetIdFromHandle(bobHandleTwo), 1n]
      ]),
      coins: 1_724_100n
    }
  }
};

export const userTokenAssetName = Asset.AssetNameLabel.encode(
  handleAssetName(maryHandleOne),
  Asset.AssetNameLabelNum.UserNFT
);
export const referenceTokenAssetName = Asset.AssetNameLabel.encode(
  handleAssetName(maryHandleOne),
  Asset.AssetNameLabelNum.ReferenceNFT
);
export const scriptAddress = bobAddress;
export const handleDatum = Serialization.PlutusData.fromCbor(
  HexBlob(
    // https://cexplorer.io/datum/8b828de43929ce9a10ac218cc690360f69eb50b42e6a3a2f92d05ea8ca6bf288
    'd8799faa446e616d654a24706861726d6572733245696d6167655838697066733a2f2f7a646a37576d6f5a3656793564334b3675714253525a50527a5365625678624c326e315741514e4158336f4c6157655974496d65646961547970654a696d6167652f6a706567426f6700496f675f6e756d6265720046726172697479456261736963466c656e677468094a636861726163746572734f6c6574746572732c6e756d62657273516e756d657269635f6d6f64696669657273404776657273696f6e0101b34862675f696d6167655835697066733a2f2f516d59365869714272394a4e6e75677554527378336f63766b51656d4e4a356943524d6965383577717a39344a6f497066705f696d6167655835697066733a2f2f516d57676a58437856555357507931576d5556336a6f505031735a4d765a3731736f3671793643325a756b52424446706f7274616c404864657369676e65725838697066733a2f2f7a623272686b3278453154755757787448547a6f356774446945784136547276534b69596e6176704552334c66446b6f4b47736f6369616c73404676656e646f72404764656661756c74004e7374616e646172645f696d6167655838697066733a2f2f7a62327268696b435674535a7a4b756935336b76574c387974564374637a67457239424c6a466258423454585578684879536c6173745f7570646174655f61646472657373583901e80fd3030bfb17f25bfee50d2e71c9ece68292915698f955ea6645ea2b7be012268a95ebaefe5305164405df22ce4119a4a3549bbf1cda3d4c76616c6964617465645f6279581c4da965a049dfd15ed1ee19fba6e2974a0b79fc416dd1796a1f97f5e14a696d6167655f686173685820bcd58c0dceea97b717bcbe0edc40b2e65fc2329a4db9ce3716b47b90eb5167de537374616e646172645f696d6167655f686173685820b3d06b8604acc91729e4d10ff5f42da4137cbb6b943291f703eb97761673c9804b7376675f76657273696f6e46312e31352e304c6167726565645f7465726d7340546d6967726174655f7369675f726571756972656400446e7366770045747269616c00497066705f61737365745823e74862a09d17a9cb03174a6bd5fa305b8684475c4c36021591c606e0445030363831364862675f6173736574582c9bdf437b6831d46d92d0db80f19f1b702145e9fdcc43c6264f7a04dc001bc2805468652046726565204f6e65ff'
  )
).toCore();

export const userNftOutput: Cardano.TxOut = {
  address: maryAddress,
  value: {
    assets: new Map([[Cardano.AssetId.fromParts(handlePolicyId, userTokenAssetName), 1n]]),
    coins: 123n
  }
};

export const referenceNftOutput: Cardano.TxOut = {
  address: scriptAddress,
  datum: handleDatum,
  value: {
    assets: new Map([[Cardano.AssetId.fromParts(handlePolicyId, referenceTokenAssetName), 1n]]),
    coins: 123n
  }
};
