import * as Crypto from '../../src';

import { arc52Vectors } from '../ARC52TestVectors';

const Uint8ArrayToHexString = (b: Uint8Array) => Buffer.from(b).toString('hex');

/**
 * Test the given Bip32Ed25519 concrete implementation.
 *
 * @param name The name of the implementation.
 * @param bip32Ed25519 The concrete instance.
 */
const testARC52 = (name: string, bip32Ed25519: Crypto.Bip32Ed25519) => {
  describe(name, () => {
    it('derive private and public key key', async () => {
      for (const vector of arc52Vectors) {
        const rootKeyHex = Uint8ArrayToHexString(vector.rootKey);
        const generatedPrivateKeyHex = Crypto.Bip32PrivateKeyHex(Uint8ArrayToHexString(vector.generatedPrivateKey));
        const generatedPublicKeyHex = Uint8ArrayToHexString(vector.generatedPublicKey);

        const calculatedPrivateKeyHex = await bip32Ed25519.derivePrivateKey(
          Crypto.Bip32PrivateKeyHex(rootKeyHex),
          vector.bip44path
        );

        // getBip32PublicKey(.) concatenates an additional 64 bytes:
        // this.#key.slice(CHAIN_CODE_INDEX, CHAIN_CODE_INDEX + CHAIN_CODE_SIZE)
        // but the actual public key is only the first 64 bytes of the key.
        const calculatedPublicKeyHex = (await bip32Ed25519.getBip32PublicKey(calculatedPrivateKeyHex)).slice(0, 64);

        expect(calculatedPrivateKeyHex).toBe(generatedPrivateKeyHex);
        expect(calculatedPublicKeyHex).toBe(generatedPublicKeyHex);
      }
    });
  });
};

testARC52('SodiumBip32Ed25519', new Crypto.SodiumBip32Ed25519());
