/* eslint-disable max-len */
import { CSL, Cardano } from '../../../src';
import { Ed25519KeyHash } from '../../../src/Cardano';

describe('Cardano/types/Key', () => {
  it('Ed25519PublicKey() accepts a valid public key hex string', () => {
    expect(() =>
      Cardano.Ed25519PublicKey('6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39')
    ).not.toThrow();
    expect(() =>
      Cardano.Ed25519PublicKey.fromHexBlob(
        Cardano.util.HexBlob('6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39')
      )
    ).not.toThrow();
  });

  it('Ed25519PrivateKey() accepts a valid private key hex string', () => {
    expect(() =>
      Cardano.Ed25519PrivateKey(
        '6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d396199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39'
      )
    ).not.toThrow();
    expect(() =>
      Cardano.Ed25519PrivateKey.fromHexBlob(
        Cardano.util.HexBlob(
          '6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d396199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39'
        )
      )
    ).not.toThrow();
  });

  describe('Ed25519KeyHash', () => {
    it('accepts a key hash hex string', () => {
      expect(() => Cardano.Ed25519KeyHash('6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed5')).not.toThrow();
    });

    it('is of same length as in CSL', () => {
      expect(() =>
        CSL.Ed25519KeyHash.from_bytes(
          Buffer.from(Cardano.Ed25519KeyHash('6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed5'), 'hex')
        )
      ).not.toThrow();
    });

    test('fromRewardAccount', () => {
      const rewardAccount = Cardano.RewardAccount('stake1u89sasnfyjtmgk8ydqfv3fdl52f36x3djedfnzfc9rkgzrcss5vgr');
      expect(() => Ed25519KeyHash.fromRewardAccount(rewardAccount)).not.toThrow();
    });
  });

  it('Bip32PublicKey() accepts a valid public key hex string', () => {
    expect(() =>
      Cardano.Bip32PublicKey(
        '6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d396199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39'
      )
    ).not.toThrow();
    expect(() =>
      Cardano.Bip32PublicKey.fromHexBlob(
        Cardano.util.HexBlob(
          '6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d396199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39'
        )
      )
    ).not.toThrow();
  });

  it('Bip32PrivateKey() accepts a valid public key hex string', () => {
    expect(() =>
      Cardano.Bip32PrivateKey(
        '6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d36199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d3996199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39'
      )
    ).not.toThrow();
    expect(() =>
      Cardano.Bip32PrivateKey.fromHexBlob(
        Cardano.util.HexBlob(
          '6199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d36199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d3996199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d39'
        )
      )
    ).not.toThrow();
  });
});
